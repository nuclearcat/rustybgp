//! Public GoBGP v4 API compatibility tests using synthetic BGP wire fixtures.
use super::*;

async fn delete(svc: &GrpcService, uuid: Vec<u8>) -> Result<(), tonic::Status> {
    svc.delete_path(tonic::Request::new(api::DeletePathRequest {
        uuid,
        ..Default::default()
    }))
    .await
    .map(|_| ())
}

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
        table_type: api::TableType::Global as i32,
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

#[tokio::test]
async fn legacy_withdraw_and_uuid_delete_work_for_unicast_and_flowspec() {
    for family in [
        Family::IPV4,
        Family::IPV6,
        Family::IPV4_FLOWSPEC,
        Family::IPV6_FLOWSPEC,
    ] {
        let svc = make_grpc_service();
        let path = binary_path(family);
        let old_uuid = add(&svc, path.clone()).await.unwrap().uuid;
        let withdrawal = api::Path {
            is_withdraw: true,
            ..path.clone()
        };
        assert!(add(&svc, withdrawal.clone()).await.unwrap().uuid.is_empty());
        assert!(svc.tables.collect_loc_rib_paths(family).is_empty());
        // Withdrawing an absent path is idempotent.
        assert!(add(&svc, withdrawal).await.unwrap().uuid.is_empty());
        let new_uuid = add(&svc, path).await.unwrap().uuid;
        assert_eq!(
            delete(&svc, old_uuid).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(svc.tables.collect_loc_rib_paths(family).len(), 1);
        delete(&svc, new_uuid).await.unwrap();
        assert!(svc.tables.collect_loc_rib_paths(family).is_empty());
    }
}

#[tokio::test]
async fn legacy_withdraw_is_scoped_to_local_source_prefix_and_path_id() {
    let svc = make_grpc_service();
    let path = binary_path(Family::IPV4);
    let nlri = packet::Nlri::decode_from_bytes(Family::IPV4, &path.nlri_binary).unwrap();
    let peer = Arc::new(table::Source::new(
        "192.0.2.2".parse().unwrap(),
        "192.0.2.1".parse().unwrap(),
        65002,
        65001,
        "192.0.2.2".parse().unwrap(),
        table::PeerRole::Ebgp,
    ));
    svc.tables.insert_route(
        peer.clone(),
        Family::IPV4,
        packet::PathNlri::new(nlri),
        Some(bgp::Nexthop::V4("192.0.2.2".parse().unwrap())),
        Arc::new(vec![packet::Attribute::empty_as_path()]),
        None,
        0,
    );
    add(&svc, path.clone()).await.unwrap();
    let other_id_uuid = add(
        &svc,
        api::Path {
            identifier: 7,
            ..path.clone()
        },
    )
    .await
    .unwrap()
    .uuid;
    let other_prefix_uuid = add(&svc, ipv4_path("10.0.0.0", 24, "192.0.2.1"))
        .await
        .unwrap()
        .uuid;
    add(
        &svc,
        api::Path {
            is_withdraw: true,
            ..path
        },
    )
    .await
    .unwrap();
    let paths = svc.tables.collect_loc_rib_paths(Family::IPV4);
    assert_eq!(paths.len(), 2);
    let target = paths
        .iter()
        .find(|p| p.net.to_string() == "198.51.100.42/32")
        .unwrap();
    assert_eq!(target.current_paths.len(), 2); // remote + local path ID 7
    assert!(
        target
            .current_paths
            .iter()
            .any(|p| Arc::ptr_eq(&p.source, &peer))
    );
    delete(&svc, other_id_uuid).await.unwrap();
    delete(&svc, other_prefix_uuid).await.unwrap();
    let remaining = svc.tables.collect_loc_rib_paths(Family::IPV4);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].current_paths.len(), 1);
    assert!(Arc::ptr_eq(&remaining[0].current_paths[0].source, &peer));
}

#[tokio::test]
async fn structured_legacy_withdraw_needs_only_nlri() {
    let svc = make_grpc_service();
    let mut path = ipv4_path("10.0.0.0", 24, "192.0.2.1");
    add(&svc, path.clone()).await.unwrap();
    path.is_withdraw = true;
    path.pattrs.clear();
    add(&svc, path).await.unwrap();
    assert!(svc.tables.collect_loc_rib_paths(Family::IPV4).is_empty());
}

async fn list(svc: &GrpcService, request: api::ListPathRequest) -> Vec<api::Destination> {
    svc.list_path(tonic::Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .map(|r| r.unwrap().destination.unwrap())
        .collect()
        .await
}

#[tokio::test]
async fn list_path_returns_binary_nexthops_and_flowspec_nlri() {
    for family in [
        Family::IPV4,
        Family::IPV6,
        Family::IPV4_FLOWSPEC,
        Family::IPV6_FLOWSPEC,
    ] {
        let svc = make_grpc_service();
        let path = binary_path(family);
        add(&svc, path.clone()).await.unwrap();
        for only_binary in [false, true] {
            let results = list(
                &svc,
                api::ListPathRequest {
                    table_type: api::TableType::Global as i32,
                    family: path.family,
                    enable_attribute_binary: true,
                    enable_nlri_binary: only_binary,
                    enable_only_binary: only_binary,
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(results.len(), 1);
            let returned = &results[0].paths[0];
            assert_eq!(returned.nlri.is_none(), only_binary);
            assert_eq!(returned.pattrs.is_empty(), only_binary);
            if only_binary {
                assert_eq!(returned.nlri_binary, path.nlri_binary);
            } else {
                assert!(returned.nlri_binary.is_empty());
            }
            // Compare the complete MP_REACH body, including its NLRI.
            for expected in &path.pattrs_binary {
                let expected = packet::Attribute::decode_from_bytes(expected).unwrap();
                let matches: Vec<_> = returned
                    .pattrs_binary
                    .iter()
                    .map(|a| packet::Attribute::decode_from_bytes(a).unwrap())
                    .filter(|a| a.code() == expected.code())
                    .collect();
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].binary(), expected.binary());
                assert_eq!(matches[0].value(), expected.value());
            }
            if !only_binary && family != Family::IPV4 {
                let mp = returned
                    .pattrs
                    .iter()
                    .find_map(|a| match &a.attr {
                        Some(api::attribute::Attr::MpReach(mp)) => Some(mp),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(mp.family, path.family);
                assert_eq!(mp.nlris, vec![returned.nlri.clone().unwrap()]);
                assert_eq!(mp.next_hops.is_empty(), family.safi() == 133);
            }
        }
        add(
            &svc,
            api::Path {
                is_withdraw: true,
                ..path
            },
        )
        .await
        .unwrap();
        assert!(
            list(
                &svc,
                api::ListPathRequest {
                    table_type: api::TableType::Global as i32,
                    family: Some(convert::family_to_api(family)),
                    enable_only_binary: true,
                    ..Default::default()
                }
            )
            .await
            .is_empty()
        );
    }
}

#[tokio::test]
async fn binary_exact_prefix_lookup_excludes_other_routes() {
    let svc = make_grpc_service();
    let path = binary_path(Family::IPV4);
    add(&svc, path.clone()).await.unwrap();
    add(&svc, ipv4_path("10.0.0.0", 24, "192.0.2.1"))
        .await
        .unwrap();
    let results = list(
        &svc,
        api::ListPathRequest {
            table_type: api::TableType::Global as i32,
            family: path.family,
            enable_only_binary: true,
            prefixes: vec![api::TableLookupPrefix {
                prefix: "198.51.100.42/32".into(),
                r#type: api::table_lookup_prefix::Type::Exact as i32,
                ..Default::default()
            }],
            ..Default::default()
        },
    )
    .await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].prefix, "198.51.100.42/32");
    assert_eq!(results[0].paths[0].nlri_binary, path.nlri_binary);
}

#[tokio::test]
async fn binary_requests_round_trip_over_grpc() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(GoBgpServiceServer::new(make_grpc_service()))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stop_rx.await;
                },
            )
            .await
            .unwrap();
    });
    let mut client =
        api::go_bgp_service_client::GoBgpServiceClient::connect(format!("http://{address}"))
            .await
            .unwrap();
    for family in [
        Family::IPV4,
        Family::IPV6,
        Family::IPV4_FLOWSPEC,
        Family::IPV6_FLOWSPEC,
    ] {
        let path = binary_path(family);
        let request = api::AddPathRequest {
            table_type: api::TableType::Global as i32,
            path: Some(path.clone()),
            ..Default::default()
        };
        let uuid = client
            .add_path(request.clone())
            .await
            .unwrap()
            .into_inner()
            .uuid;
        assert_eq!(uuid.len(), 16);
        let list_request = api::ListPathRequest {
            table_type: api::TableType::Global as i32,
            family: path.family,
            enable_only_binary: true,
            ..Default::default()
        };
        let mut stream = client
            .list_path(list_request.clone())
            .await
            .unwrap()
            .into_inner();
        let destination = stream
            .message()
            .await
            .unwrap()
            .unwrap()
            .destination
            .unwrap();
        assert_eq!(destination.paths[0].nlri_binary, path.nlri_binary);
        assert!(!destination.paths[0].pattrs_binary.is_empty());
        assert!(stream.message().await.unwrap().is_none());
        let response = client
            .add_path(api::AddPathRequest {
                path: Some(api::Path {
                    is_withdraw: true,
                    ..path
                }),
                ..request
            })
            .await
            .unwrap()
            .into_inner();
        assert!(response.uuid.is_empty());
        let mut stream = client.list_path(list_request).await.unwrap().into_inner();
        assert!(stream.message().await.unwrap().is_none());
    }
    drop(client);
    stop_tx.send(()).unwrap();
    server.await.unwrap();
}
