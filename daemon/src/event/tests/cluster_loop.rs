use super::*;

fn attrs(cluster: Ipv4Addr) -> Arc<Vec<packet::Attribute>> {
    Arc::new(vec![
        packet::Attribute::new_with_value(packet::Attribute::ORIGIN, 0).unwrap(),
        packet::Attribute::new_with_bin(packet::Attribute::CLUSTER_LIST, cluster.octets().to_vec())
            .unwrap(),
    ])
}

fn rr_params(addr: &str, cluster: Option<Ipv4Addr>) -> PeerParams {
    let mut params = default_peer_params(addr.parse().unwrap());
    params.local_asn = 65001;
    params.expected_remote_asn = 65001;
    params.route_reflector = RouteReflectorConfig {
        route_reflector_client: true,
        route_reflector_cluster_id: cluster,
    };
    params
}

#[tokio::test]
async fn cluster_loop_checks_all_local_clusters_from_clients_and_non_clients() {
    let global = make_global();
    let cid = Ipv4Addr::new(1, 2, 3, 4);
    let default_cid = global.read().await.router_id;
    {
        let mut g = global.write().await;
        g.add_peer(rr_params("10.0.0.3", Some(cid)), None).unwrap();
        g.add_peer(rr_params("10.0.0.4", None), None).unwrap();
    }
    for role in [PeerRole::Ibgp, PeerRole::IbgpRrClient] {
        let tables = make_tables();
        let peer = "10.0.0.2".parse().unwrap();
        let mut session = PeerSession::new_for_test(peer, make_context(), tables.clone());
        session.export_ctx.role = role;
        session.local_cluster_ids = global.read().await.local_cluster_ids.clone();
        session.source.insert(
            Family::IPV4,
            Arc::new(table::Source::new(
                peer,
                "10.0.0.1".parse().unwrap(),
                65001,
                65001,
                "2.0.0.2".parse().unwrap(),
                role,
            )),
        );
        for cluster in [cid, default_cid] {
            assert!(
                !session
                    .rx_update(reach_set("5.202.112.0/24"), None, attrs(cluster), 0)
                    .await
            );
            assert_eq!(tables.table_state(Family::IPV4).num_destination, 0);
        }
        assert_eq!(session.receive_diagnostics.cluster_loop.prefixes, 2);
        // A reflection path through a different cluster is valid.
        session
            .rx_update(
                reach_set("5.202.112.0/24"),
                None,
                attrs(Ipv4Addr::new(9, 8, 7, 6)),
                0,
            )
            .await;
        assert_eq!(tables.table_state(Family::IPV4).num_destination, 1);
        // ORIGINATOR_ID protection still applies to ordinary iBGP speakers.
        let originator = Arc::new(vec![
            packet::Attribute::new_with_value(
                packet::Attribute::ORIGINATOR_ID,
                u32::from(session.local_router_id),
            )
            .unwrap(),
        ]);
        session
            .rx_update(reach_set("5.202.113.0/24"), None, originator, 0)
            .await;
        assert_eq!(session.receive_diagnostics.originator_loop.prefixes, 1);
        assert_eq!(tables.table_state(Family::IPV4).num_destination, 1);
    }
}

#[tokio::test]
async fn cluster_loop_configuration_updates_existing_sessions() {
    let svc = make_unstarted_grpc_service();
    let cid = Ipv4Addr::new(1, 2, 3, 4);
    let new_cid = Ipv4Addr::new(5, 6, 7, 8);
    // Hold the same shared reference that an already-established session uses.
    let ids = svc.global.read().await.local_cluster_ids.clone();
    assert!(ids.load().is_empty());
    {
        let mut g = svc.global.write().await;
        g.asn = 65001;
        g.router_id = Ipv4Addr::new(1, 0, 0, 1);
        // A cluster-id alone does not enable route reflection.
        let mut plain = rr_params("10.0.0.2", Some(cid));
        plain.route_reflector.route_reflector_client = false;
        g.add_peer(plain, None).unwrap();
        assert!(ids.load().is_empty());
        g.add_peer(rr_params("10.0.0.3", Some(cid)), None).unwrap();
        g.add_peer(rr_params("10.0.0.4", Some(cid)), None).unwrap();
    }
    assert_eq!(ids.load().len(), 1);
    assert!(ids.load().contains(&cid));
    let mut api_peer: api::Peer = {
        let g = svc.global.read().await;
        (&g.peers[&"10.0.0.3".parse::<IpAddr>().unwrap()].view(false)).into()
    };
    api_peer.conf = Some(api::PeerConf {
        neighbor_address: "10.0.0.3".to_string(),
        local_asn: 65001,
        peer_asn: 65001,
        ..Default::default()
    });
    api_peer
        .route_reflector
        .as_mut()
        .unwrap()
        .route_reflector_cluster_id = new_cid.to_string();
    svc.update_peer(tonic::Request::new(api::UpdatePeerRequest {
        peer: Some(api_peer),
        ..Default::default()
    }))
    .await
    .unwrap();
    assert!(ids.load().contains(&cid));
    assert!(ids.load().contains(&new_cid));
    for (addr, removed) in [("10.0.0.3", new_cid), ("10.0.0.4", cid)] {
        svc.delete_peer(tonic::Request::new(api::DeletePeerRequest {
            address: addr.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap();
        assert!(!ids.load().contains(&removed));
    }
    assert!(ids.load().is_empty());
}
