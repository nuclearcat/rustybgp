//! Session-local diagnostics for announcements lost before RIB insertion.
use super::*;

#[derive(Default, Debug)]
pub(super) struct RejectionCount {
    pub(super) updates: u64,
    pub(super) prefixes: u64,
}

impl RejectionCount {
    // Log the first occurrence and powers of two to bound log volume during
    // a full-table transfer. Prefixes count announcements, not unique routes.
    fn record(&mut self, prefixes: u64) -> bool {
        self.updates += 1;
        self.prefixes += prefixes;
        self.updates.is_power_of_two()
    }
}

#[derive(Default, Debug)]
pub(super) struct ReceiveDiagnostics {
    updates: u64,
    announced: u64,
    attribute_errors: u64,
    pub(super) validation: RejectionCount,
    pub(super) as_loop: RejectionCount,
    pub(super) originator_loop: RejectionCount,
    pub(super) cluster_loop: RejectionCount,
}

impl ReceiveDiagnostics {
    /// Count announcements before validation, including batches later converted
    /// to withdrawals. Attribute errors may only discard an attribute, so they
    /// are reported separately from actual announcement rejection.
    pub(super) fn observe(&mut self, peer: IpAddr, parsed: &bgp::ParsedMessage) -> u64 {
        let bgp::ParsedMessage::Update(bgp::ParsedUpdate::Routes {
            reach,
            mp_reach,
            error_attrs,
            ..
        }) = parsed
        else {
            return 0;
        };
        self.updates += 1;
        let announced = reach
            .iter()
            .chain(mp_reach.iter())
            .map(|r| r.entries.len() as u64)
            .sum();
        self.announced += announced;
        if !error_attrs.is_empty() {
            self.attribute_errors += 1;
            if self.attribute_errors.is_power_of_two() {
                let sample = reach
                    .iter()
                    .chain(mp_reach.iter())
                    .find_map(|r| r.entries.first());
                log::warn!(
                    "{peer}: UPDATE attribute errors {error_attrs:?}; announced={announced}, sample={sample:?}, affected_updates={}",
                    self.attribute_errors,
                );
            }
        }
        announced
    }

    pub(super) fn validated(&mut self, peer: IpAddr, announced: u64, retained: u64) {
        let dropped = announced.saturating_sub(retained);
        if dropped != 0 && self.validation.record(dropped) {
            log::warn!(
                "{peer}: UPDATE validation converted announcements to withdrawals; batch_prefixes={dropped}, total={:?}",
                self.validation,
            );
        }
        if announced != 0 && self.updates.is_multiple_of(65_536) {
            log::info!(
                "{peer}: session receive totals (prefixes count announcements, not unique routes): {self:?}"
            );
        }
    }

    pub(super) fn reject(
        peer: IpAddr,
        reason: &str,
        count: &mut RejectionCount,
        family: Family,
        entries: &[packet::PathNlri],
    ) {
        if count.record(entries.len() as u64) {
            log::warn!(
                "{peer}: rejecting UPDATE announcements: {reason}; family={family:?}, sample={:?}, total={count:?}",
                entries.first(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Feed actual wire attributes through both the parser and validator: valid
    // routes, attribute-discard, and treat-as-withdraw must be distinguishable.
    #[test]
    fn distinguishes_attribute_discard_from_rejected_announcements() {
        for (extra, expected_rejected) in [
            (vec![], 0),
            (vec![0x80, 4, 3, 0, 0, 0], 0), // malformed optional MED
            (vec![0xc0, 8, 3, 0, 0, 0], 3), // malformed transitive COMMUNITY
        ] {
            let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
            attrs.extend_from_slice(&1299u32.to_be_bytes());
            attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1]);
            attrs.extend(extra);
            let prefixes = [8, 10, 16, 172, 16, 24, 192, 0, 2];
            let mut wire = vec![0xff; 16];
            wire.extend_from_slice(&((23 + attrs.len() + prefixes.len()) as u16).to_be_bytes());
            wire.push(2);
            wire.extend_from_slice(&[0, 0]);
            wire.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
            wire.extend(attrs);
            wire.extend(prefixes);
            let caps = [
                packet::Capability::MultiProtocol(Family::IPV4),
                packet::Capability::FourOctetAsNumber(9002),
            ];
            let parsed = bgp::PeerCodec::negotiate(&caps, &caps)
                .parse_message(&wire)
                .unwrap();
            let mut diagnostics = ReceiveDiagnostics::default();
            let peer = "192.0.2.2".parse().unwrap();
            let announced = diagnostics.observe(peer, &parsed);
            let retained = bgp::validate_message(parsed, false)
                .unwrap()
                .map(|msg| match msg {
                    bgp::Message::Update(bgp::Update::Reach { entries, .. }) => {
                        entries.len() as u64
                    }
                    _ => 0,
                })
                .sum();
            diagnostics.validated(peer, announced, retained);
            assert_eq!(announced, 3);
            assert_eq!(diagnostics.validation.prefixes, expected_rejected);
            assert_eq!(
                diagnostics.validation.updates,
                u64::from(expected_rejected != 0)
            );
        }
    }
}
