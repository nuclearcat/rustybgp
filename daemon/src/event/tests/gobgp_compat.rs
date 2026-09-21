//! Public GoBGP v4 API compatibility tests using synthetic BGP wire fixtures.
use super::*;

fn binary_path(family: Family) -> api::Path {
    let ipv6 = family.afi() == 2;
    let flowspec = family.safi() == 133;
    let address = if ipv6 {
        "2001:db8::42"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    } else {
        vec![198, 51, 100, 42]
    };
    let mut prefix = vec![if ipv6 { 128 } else { 32 }];
    if flowspec && ipv6 {
        prefix.push(0); // IPv6 FlowSpec prefix offset
    }
    prefix.extend(address);
    let nlri = if flowspec {
        let mut body = vec![1]; // destination prefix
        body.extend(prefix);
        body.extend([3, 0x81, 17, 5, 0x81, 53]); // UDP, destination port 53
        let mut nlri = vec![body.len() as u8];
        nlri.extend(body);
        nlri
    } else {
        prefix
    };
    let mut attrs = vec![vec![0x40, 1, 1, 0]]; // ORIGIN IGP
    if family == Family::IPV4 {
        attrs.push(vec![0x40, 3, 4, 192, 0, 2, 1]);
    } else {
        let nh = if flowspec {
            vec![]
        } else {
            "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()
        };
        let mut mp = vec![0, family.afi() as u8, family.safi(), nh.len() as u8];
        mp.extend(nh);
        mp.push(0); // reserved
        mp.extend(&nlri);
        let mut attr = vec![0x80, 14, mp.len() as u8];
        attr.extend(mp);
        attrs.push(attr);
    }
    if flowspec {
        attrs.push(vec![0xc0, 16, 8, 0x80, 6, 0, 0, 0, 0, 0, 0]); // discard
    }
    attrs.push(vec![0xc0, 8, 4, 0xfd, 0xe8, 0x03, 0x85]); // 65000:901
    api::Path {
        family: Some(convert::family_to_api(family)),
        nlri_binary: nlri,
        pattrs_binary: attrs,
        ..Default::default()
    }
}

async fn add(svc: &GrpcService, path: api::Path) -> Result<api::AddPathResponse, tonic::Status> {
    svc.add_path(tonic::Request::new(api::AddPathRequest {
        path: Some(path),
        ..Default::default()
    }))
    .await
    .map(tonic::Response::into_inner)
}

#[tokio::test]
async fn binary_announcements_preserve_nlri_attributes_and_nexthop() {
    for family in [
        Family::IPV4,
        Family::IPV6,
        Family::IPV4_FLOWSPEC,
        Family::IPV6_FLOWSPEC,
    ] {
        let svc = make_grpc_service();
        let path = binary_path(family);
        let expected_nlri = path.nlri_binary.clone();
        let uuid = add(&svc, path).await.unwrap().uuid;
        assert_eq!(uuid.len(), 16);
        let paths = svc.tables.collect_loc_rib_paths(family);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].net.encode_to_bytes(), expected_nlri);
        let attrs = &paths[0].new_best().unwrap().attr;
        assert!(attrs.iter().any(|a| a.code() == bgp::Attribute::COMMUNITY
            && a.binary().unwrap() == &[0xfd, 0xe8, 0x03, 0x85]));
        if family.safi() == 133 {
            assert!(paths[0].new_best().unwrap().nexthop.is_none());
            assert!(
                attrs
                    .iter()
                    .any(|a| a.code() == bgp::Attribute::EXTENDED_COMMUNITY
                        && a.binary().unwrap() == &[0x80, 6, 0, 0, 0, 0, 0, 0])
            );
        } else {
            let expected = if family == Family::IPV4 {
                "192.0.2.1"
            } else {
                "2001:db8::1"
            };
            assert_eq!(
                paths[0]
                    .new_best()
                    .unwrap()
                    .nexthop
                    .unwrap()
                    .addr()
                    .to_string(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn binary_fields_take_precedence_over_structured_fields() {
    let svc = make_grpc_service();
    let mut path = binary_path(Family::IPV4);
    let structured = ipv4_path("10.0.0.0", 24, "10.0.0.1");
    path.nlri = structured.nlri;
    path.pattrs = structured.pattrs;
    add(&svc, path).await.unwrap();
    let paths = svc.tables.collect_loc_rib_paths(Family::IPV4);
    assert_eq!(paths[0].net.to_string(), "198.51.100.42/32");
    assert_eq!(
        paths[0]
            .new_best()
            .unwrap()
            .nexthop
            .unwrap()
            .addr()
            .to_string(),
        "192.0.2.1"
    );
}

#[tokio::test]
async fn binary_extended_length_attributes_are_accepted() {
    let svc = make_grpc_service();
    let mut path = binary_path(Family::IPV4);
    let communities = [0xfd, 0xe8, 0x03, 0x85].repeat(70);
    let mut attr = vec![0xd0, 8, 1, 24]; // extended length: 280 bytes
    attr.extend(&communities);
    *path.pattrs_binary.last_mut().unwrap() = attr;
    add(&svc, path).await.unwrap();
    let paths = svc.tables.collect_loc_rib_paths(Family::IPV4);
    let attrs = &paths[0].new_best().unwrap().attr;
    assert_eq!(
        attrs
            .iter()
            .find(|a| a.code() == 8)
            .unwrap()
            .binary()
            .unwrap(),
        &communities
    );
}

#[tokio::test]
async fn malformed_binary_requests_do_not_install_routes() {
    let valid = binary_path(Family::IPV4);
    let mut bad_paths = vec![];
    for nlri in [vec![33, 1, 2, 3, 4, 5], vec![32, 1], vec![0, 0]] {
        bad_paths.push(api::Path {
            nlri_binary: nlri,
            ..valid.clone()
        });
    }
    for attr in [
        vec![0x40],
        vec![0x40, 1, 2, 0],
        vec![0x40, 1, 1, 3],
        vec![0xc0, 8, 3, 1, 2, 3],
        vec![0x40, 3, 1, 1],
        vec![0x80, 14, 1, 0],
    ] {
        bad_paths.push(api::Path {
            pattrs_binary: vec![attr],
            ..valid.clone()
        });
    }
    let mut duplicate = valid.clone();
    duplicate
        .pattrs_binary
        .push(duplicate.pattrs_binary[0].clone());
    bad_paths.push(duplicate);
    for path in bad_paths {
        let svc = make_grpc_service();
        assert_eq!(
            add(&svc, path).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert!(svc.tables.collect_loc_rib_paths(Family::IPV4).is_empty());
    }
}
