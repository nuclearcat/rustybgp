use super::*;
use tokio::io::AsyncReadExt;

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut wire = vec![0xff; 16];
    wire.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    wire.push(kind);
    wire.extend_from_slice(body);
    wire
}

async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 19];
    stream.read_exact(&mut header).await.unwrap();
    let len = u16::from_be_bytes([header[16], header[17]]) as usize;
    let mut wire = header.to_vec();
    wire.resize(len, 0);
    stream.read_exact(&mut wire[19..]).await.unwrap();
    wire
}

fn update(attrs: &[u8], reach: &[u8], withdrawn: &[u8]) -> Vec<u8> {
    let mut body = (withdrawn.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(withdrawn);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(reach);
    frame(2, &body)
}

async fn wait_prefixes(tables: &TableHandle, peer: IpAddr, expected: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let stats = tables.collect_peer_stats(&[peer]);
            if stats
                .get(&peer)
                .and_then(|s| s.get(&Family::IPV4))
                .is_some_and(|s| s.received == expected && s.accepted == expected)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("peer route counters did not converge");
}

#[tokio::test]
async fn ipv4_session_receives_ipv6_nexthop_without_remote_capability() {
    for role in [crate::fsm::Role::Active, crate::fsm::Role::Passive] {
        let global = make_global();
        let tables = make_tables();
        let (mut client, server) = loopback_pair().await;
        let peer_addr = client.local_addr().unwrap().ip();
        {
            let mut g = global.write().await;
            g.asn = 9002;
            g.router_id = "217.28.63.34".parse().unwrap();
            let mut params = default_peer_params(peer_addr);
            params.local_asn = 9002;
            params.expected_remote_asn = 9002;
            params.passive = true; // Do not initiate retries after test teardown.
            params.families.insert(Family::IPV4, 0);
            g.add_peer(params, None).unwrap();
        }
        let session = accept_connection(&global, &tables, server, role)
            .await
            .unwrap();
        let (active_tx, _active_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(session.run(global.clone(), active_tx));

        tokio::time::timeout(Duration::from_secs(5), async {
            let open = bgp::PeerCodec::new()
                .parse_message(&read_frame(&mut client).await)
                .unwrap();
            let bgp::ParsedMessage::Open(open) = open else {
                panic!("expected OPEN")
            };
            assert!(
                open.capability.iter().any(|c| matches!(c,
                    packet::Capability::ExtendedNexthop(tuples)
                        if tuples.contains(&(Family::IPV4, Family::AFI_IP6))
                )),
                "{role:?}: advertise RFC 8950 on IPv4 transport"
            );

            // Match the reported peer: IPv4 + AS4, but no Extended Nexthop
            // capability. Our advertisement alone permits it to send us an
            // IPv6 next hop; its advertisement would govern the reverse direction.
            let remote_open = bgp::Message::Open(bgp::Open {
                as_number: 9002,
                holdtime: HoldTime::new(90).unwrap(),
                router_id: u32::from("87.245.225.162".parse::<Ipv4Addr>().unwrap()),
                capability: vec![
                    packet::Capability::MultiProtocol(Family::IPV4),
                    packet::Capability::FourOctetAsNumber(9002),
                ],
            });
            let mut wire = bytes::BytesMut::new();
            bgp::PeerCodec::new()
                .encode_to(&remote_open, &mut wire)
                .unwrap();
            client.write_all(&wire).await.unwrap();
            assert_eq!(read_frame(&mut client).await[18], 4); // KEEPALIVE
            client.write_all(&frame(4, &[])).await.unwrap();
        })
        .await
        .expect("BGP handshake timed out");

        let next_hop: Ipv6Addr = "2001:db8::1234".parse().unwrap();
        // Hand-built wire fixture, independent of RustyBGP's UPDATE encoder.
        let mut common = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1];
        common.extend_from_slice(&1299u32.to_be_bytes());
        common.extend_from_slice(&[0x40, 5, 4, 0, 0, 0, 100]);
        let prefixes = [24, 198, 51, 100, 24, 203, 0, 113];
        let mut mp = vec![0, 1, 1, 16];
        mp.extend_from_slice(&next_hop.octets());
        mp.push(0);
        mp.extend_from_slice(&prefixes);
        let mut attrs = common.clone();
        attrs.extend_from_slice(&[0x80, 14, mp.len() as u8]);
        attrs.extend(mp);
        client.write_all(&update(&attrs, &[], &[])).await.unwrap();
        wait_prefixes(&tables, peer_addr, 2).await;
        let routes = tables.collect_paths(
            table::TableQuery::AdjIn(peer_addr),
            Family::IPV4,
            vec![],
            true,
        );
        assert_eq!(routes.len(), 2);
        for route in &routes {
            assert_eq!(route.paths[0].nexthop, Some(bgp::Nexthop::V6(next_hop)));
        }
        let g = global.read().await;
        let peer: api::Peer = (&g.peers[&peer_addr].view(false)).into();
        assert!(
            peer.state
                .unwrap()
                .local_cap
                .iter()
                .any(|c| matches!(c.cap, Some(api::capability::Cap::ExtendedNexthop(_))))
        );
        drop(g);

        // Legacy IPv4 NEXT_HOP announcements coexist on the same session.
        common.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1]);
        let legacy = [24, 192, 0, 2];
        client
            .write_all(&update(&common, &legacy, &[]))
            .await
            .unwrap();
        wait_prefixes(&tables, peer_addr, 3).await;

        let mut withdrawn = vec![0x80, 15, (3 + prefixes.len()) as u8, 0, 1, 1];
        withdrawn.extend(prefixes);
        client
            .write_all(&update(&withdrawn, &[], &[]))
            .await
            .unwrap();
        wait_prefixes(&tables, peer_addr, 1).await;
        client.write_all(&update(&[], &[], &legacy)).await.unwrap();
        wait_prefixes(&tables, peer_addr, 0).await;
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
