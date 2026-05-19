use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    KdeConnectCore, cleanup_device_data,
    core::connection::{
        ALLOWED_TIMESTAMP_DIFF_SECS, ConnectionHandle, PAIRING_TIMEOUT_SECS,
        UNPAIRED_RESYNC_DROP_DELAY, install_connection, is_current_connection,
        packet_allowed_for_pair_state, pair_false_packet, remove_connection,
        remove_connection_if_current, remove_pairing_attempt,
    },
    device::{Device, DeviceId, PairState},
    event::{AppEvent, ConnectionEvent, CoreEvent},
    filetransfer::TransferAdapter,
    plugin_config,
    plugins::{self, ping::Ping, share::ShareRequest},
    protocol::{DeviceFile, DevicePayload, PacketType, Pair, ProtocolPacket},
    transport::TransportEvent,
};

impl KdeConnectCore {
    pub(crate) async fn core_events(&self, event: CoreEvent) {
        match event {
            CoreEvent::PacketReceived { device, packet } => {
                info!("[core] packet received from device: {}", device);
                if let Some(device_obj) = self.device_manager.get_device(&device).await {
                    self.plugin_registry
                        .dispatch(
                            device_obj,
                            packet,
                            self.event_tx.clone(),
                            self.conn_tx.clone(),
                            self.mpris_conn_tx.clone(),
                        )
                        .await;
                }
            }
            CoreEvent::DeviceDiscovered(_device) => {
                debug!("[core] device discovered.");
            }
            CoreEvent::DevicePaired((device_id, device)) => {
                info!("[core] device paired: {}", device_id);
                remove_pairing_attempt(&self.pairing_attempts, &device_id).await;
                self.unpaired_resync_limiter.clear(&device_id).await;

                if self
                    .plugin_registry
                    .is_plugin_enabled(&device_id.0, "contacts")
                    .await
                {
                    let contacts_pkt = ProtocolPacket::new(
                        PacketType::ContactsRequestAllUidsTimestamps,
                        serde_json::json!({}),
                    );
                    let _ = self.queue_packet(&device_id, contacts_pkt).await;
                }

                if self
                    .plugin_registry
                    .is_plugin_enabled(&device_id.0, "sms")
                    .await
                {
                    let sms_pkt = ProtocolPacket::new(
                        PacketType::SmsRequestConversations,
                        serde_json::json!({}),
                    );
                    let _ = self.queue_packet(&device_id, sms_pkt).await;
                }

                // Bootstrap MPRIS: request the phone's player list so
                // expose_phone_mpris can register D-Bus proxies for them.
                if self
                    .plugin_registry
                    .is_plugin_enabled(&device_id.0, "mpris")
                    .await
                {
                    let mpris_pkt = ProtocolPacket::new(
                        PacketType::MprisRequest,
                        serde_json::to_value(crate::plugins::mpris::MprisRequest {
                            request_player_list: Some(true),
                            ..Default::default()
                        })
                        .unwrap(),
                    );
                    let _ = self.queue_packet(&device_id, mpris_pkt).await;
                }

                let conn_event = ConnectionEvent::DevicePaired((device_id, device));
                let _ = self.conn_tx.send(conn_event.clone());
                let _ = self.mpris_conn_tx.send(conn_event);
            }
            CoreEvent::DevicePairCancelled(device_id) => {
                info!("[core] device pair cancelled.");
                remove_pairing_attempt(&self.pairing_attempts, &device_id).await;
                self.unpaired_resync_limiter.clear(&device_id).await;
                plugins::systemvolume::on_device_disconnect(&device_id);
                let conn_event = ConnectionEvent::PairStateChanged((
                    device_id,
                    crate::device::PairState::NotPaired,
                ));
                let _ = self.conn_tx.send(conn_event.clone());
                let _ = self.mpris_conn_tx.send(conn_event);
            }
            CoreEvent::DevicePairStateChanged((device_id, pair_state)) => {
                if matches!(pair_state, PairState::NotPaired | PairState::Paired) {
                    remove_pairing_attempt(&self.pairing_attempts, &device_id).await;
                    self.unpaired_resync_limiter.clear(&device_id).await;
                }
                if pair_state == PairState::NotPaired {
                    plugins::systemvolume::on_device_disconnect(&device_id);
                }
                let conn_event = ConnectionEvent::PairStateChanged((device_id, pair_state));
                let _ = self.conn_tx.send(conn_event.clone());
                let _ = self.mpris_conn_tx.send(conn_event);
            }
            CoreEvent::SendPacket { device, packet } => {
                info!("[core] sending packet");
                let _ = self.queue_packet(&device, packet).await;
            }
            CoreEvent::SendPaylod {
                device,
                packet,
                payload,
                payload_size,
            } => {
                info!("[core] sending packet w/ payload");

                if !self
                    .packet_allowed_to_send(&device, &packet.packet_type)
                    .await
                {
                    warn!(
                        "[core] dropping payload packet {:?} for {} because device is not paired",
                        packet.packet_type, device
                    );
                    return;
                }

                let sender = {
                    let guard = self.writer_map.lock().await;
                    guard.get(&device).map(|handle| handle.write_tx.clone())
                };

                if let Some(sender) = sender {
                    let transfer_adapter =
                        TransferAdapter::new(payload, payload_size, self.conn_tx.clone());
                    self.plugin_registry
                        .send_payload(packet, &sender, transfer_adapter, payload_size)
                        .await;
                }
            }
            CoreEvent::Error(msg) => {
                tracing::error!("{}", msg);
            }
        };
    }

    pub(crate) async fn transport_events(&self, event: TransportEvent) {
        match event {
            TransportEvent::NewConnection {
                addr,
                id,
                name,
                write_tx,
                conn_id,
            } => {
                debug!("[core] new connection from: {}", addr);

                let meta = crate::transport::take_conn_metadata(&id).unwrap_or_else(|| {
                    crate::transport::ConnMetadata {
                        device_type: "phone".to_string(),
                        incoming_capabilities: vec![],
                        outgoing_capabilities: vec![],
                        protocol_version: 0,
                        pairing_timestamp: 0,
                        peer_certificate: vec![],
                        shutdown_tx: tokio::sync::watch::channel(false).0,
                        incoming_conn_id: 0,
                    }
                });
                let device_type = meta.device_type;
                let incoming_capabilities = meta.incoming_capabilities;
                let outgoing_capabilities = meta.outgoing_capabilities;
                let protocol_version = meta.protocol_version;
                let pairing_timestamp = meta.pairing_timestamp;
                let peer_certificate = meta.peer_certificate;
                let shutdown_tx = meta.shutdown_tx;
                debug!("[core] new connection from: {}", addr);

                let mut device = match Device::from_discovery(
                    id.0.clone(),
                    name,
                    device_type,
                    incoming_capabilities,
                    outgoing_capabilities,
                    addr,
                )
                .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("Failed to create device from metadata: {}", e);
                        return;
                    }
                };

                if device.pair_state == crate::device::PairState::Paired
                    && device.protocol_version > protocol_version
                {
                    warn!(
                        "[core] refusing protocol downgrade for paired device {}: stored={}, incoming={}",
                        id, device.protocol_version, protocol_version
                    );
                    return;
                }

                let stored_remote_certificate = device.remote_certificate.clone();
                if device.pair_state == crate::device::PairState::Paired
                    && !stored_remote_certificate.is_empty()
                    && stored_remote_certificate != peer_certificate
                {
                    warn!(
                        "[core] TLS certificate changed for paired device {}; unpairing",
                        id
                    );
                    device.remote_certificate.clear();
                    self.device_manager
                        .add_or_update_device(id.clone(), device.clone())
                        .await;
                    self.device_manager
                        .update_pair_state(&id, crate::device::PairState::NotPaired)
                        .await;
                    cleanup_device_data(&id.0).await;
                    return;
                }

                let should_backfill_certificate = device.pair_state
                    == crate::device::PairState::Paired
                    && stored_remote_certificate.is_empty()
                    && !peer_certificate.is_empty();

                if !peer_certificate.is_empty() {
                    device.remote_certificate = peer_certificate;
                }

                if should_backfill_certificate {
                    let _ = device
                        .update_pair_state(crate::device::PairState::Paired)
                        .await;
                }

                self.device_manager
                    .add_or_update_device(id.clone(), device.clone())
                    .await;

                // Store the peer's protocol version and pairing timestamp.
                self.device_manager
                    .set_protocol_version(&id, protocol_version)
                    .await;
                if pairing_timestamp > 0 {
                    self.device_manager
                        .set_pairing_timestamp(&id, pairing_timestamp)
                        .await;
                }

                install_connection(
                    &self.writer_map,
                    &self.conn_id_map,
                    id.clone(),
                    conn_id,
                    ConnectionHandle {
                        write_tx,
                        shutdown_tx,
                    },
                )
                .await;
                debug!("[core] installed connection for {}", id);

                if device.pair_state == crate::device::PairState::Paired {
                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "contacts")
                        .await
                    {
                        let contacts_pkt = ProtocolPacket::new(
                            PacketType::ContactsRequestAllUidsTimestamps,
                            serde_json::json!({}),
                        );
                        let _ = self.queue_packet(&id, contacts_pkt).await;
                    }

                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "notification")
                        .await
                    {
                        let notification_pkt = ProtocolPacket::new(
                            PacketType::NotificationRequest,
                            serde_json::json!({ "request": true }),
                        );
                        let _ = self.queue_packet(&id, notification_pkt).await;
                    }

                    if self.plugin_registry.is_plugin_enabled(&id.0, "sms").await {
                        let sms_pkt = ProtocolPacket::new(
                            PacketType::SmsRequestConversations,
                            serde_json::json!({}),
                        );
                        let _ = self.queue_packet(&id, sms_pkt).await;
                    }

                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "battery")
                        .await
                    {
                        let battery_pkt = ProtocolPacket::new(
                            PacketType::BatteryRequest,
                            serde_json::json!({ "request": true }),
                        );
                        let _ = self.queue_packet(&id, battery_pkt).await;
                        plugins::battery::send_local_state(id.clone(), self.event_tx.clone()).await;
                    }

                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "connectivity_report")
                        .await
                    {
                        let connectivity_pkt = ProtocolPacket::new(
                            PacketType::ConnectivityReportRequest,
                            serde_json::json!({}),
                        );
                        let _ = self.queue_packet(&id, connectivity_pkt).await;
                    }

                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "mousepad")
                        .await
                    {
                        let keyboard_state_pkt = ProtocolPacket::new(
                            PacketType::MousePadKeyboardState,
                            serde_json::json!({ "state": true }),
                        );
                        let _ = self.queue_packet(&id, keyboard_state_pkt).await;
                    }

                    // Send our local command list so the Android app shows
                    // the Run Command option (requires canAddCommand: true).
                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "runcommand")
                        .await
                    {
                        plugins::run_command::send_command_list(&id, self.event_tx.clone()).await;
                    }

                    if self
                        .plugin_registry
                        .is_plugin_enabled(&id.0, "systemvolume")
                        .await
                    {
                        plugins::systemvolume::on_device_connect(id.clone(), self.event_tx.clone());
                    }
                }

                let conn_event = ConnectionEvent::Connected((id.clone(), device.clone()));
                let _ = self.conn_tx.send(conn_event.clone());
                let _ = self.mpris_conn_tx.send(conn_event);
            }
            TransportEvent::IncomingPacket { addr, id, raw } => {
                let conn_id = crate::transport::CONN_METADATA
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&id).map(|m| m.incoming_conn_id))
                    .unwrap_or(0);
                if !self.is_current_connection(&id, conn_id).await {
                    info!(
                        "[core] stale packet from {} (conn_id {} != current) — ignoring",
                        id, conn_id
                    );
                    return;
                }

                info!("[core] incoming packet.");
                match serde_json::from_str::<ProtocolPacket>(&raw) {
                    Ok(pkt) => {
                        if let PacketType::Pair = pkt.packet_type {
                            if let Ok(pair_body) = serde_json::from_value::<Pair>(pkt.body.clone())
                                && let Some(device) = self.device_manager.get_device(&id).await
                            {
                                if !pair_body.pair {
                                    // Phone sent pair:false — either it's unpairing from us, or
                                    // it's a fresh device announcing it doesn't know us yet.
                                    match device.pair_state {
                                        crate::device::PairState::Paired => {
                                            info!(
                                                "[core] Phone unpairing from us — cleaning up {}",
                                                id
                                            );
                                            remove_pairing_attempt(&self.pairing_attempts, &id)
                                                .await;
                                            self.device_manager
                                                .update_pair_state(
                                                    &id,
                                                    crate::device::PairState::NotPaired,
                                                )
                                                .await;
                                            cleanup_device_data(&id.0).await;
                                            self.drop_connection(&id).await;
                                        }
                                        crate::device::PairState::Requesting
                                        | crate::device::PairState::Requested => {
                                            info!(
                                                "[core] pairing with {} was rejected/cancelled by peer",
                                                id
                                            );
                                            remove_pairing_attempt(&self.pairing_attempts, &id)
                                                .await;
                                            self.device_manager
                                                .update_pair_state(
                                                    &id,
                                                    crate::device::PairState::NotPaired,
                                                )
                                                .await;
                                            let ev = ConnectionEvent::PairingTimedOut(id.clone());
                                            let _ = self.conn_tx.send(ev.clone());
                                            let _ = self.mpris_conn_tx.send(ev);
                                        }
                                        crate::device::PairState::NotPaired => {
                                            info!(
                                                "[core] pair:false from {} — device not paired, ignoring",
                                                id
                                            );
                                        }
                                    }
                                } else {
                                    let device_name = device.name.clone();
                                    let device_id_clone = id.clone();
                                    let is_new_request = self
                                        .pairing
                                        .handle_pair_request(
                                            device.device_id,
                                            device.name,
                                            device.address,
                                            pkt,
                                        )
                                        .await
                                        .unwrap_or(false);
                                    if is_new_request {
                                        let ev = ConnectionEvent::PairingRequested((
                                            device_id_clone,
                                            device_name,
                                        ));
                                        let _ = self.conn_tx.send(ev.clone());
                                        let _ = self.mpris_conn_tx.send(ev);

                                        // 30-second auto-reject: if the user doesn't respond,
                                        // reject the pairing so neither side waits indefinitely.
                                        let dm = self.device_manager.clone();
                                        let event_tx = self.event_tx.clone();
                                        let conn_tx = self.conn_tx.clone();
                                        let mpris_tx = self.mpris_conn_tx.clone();
                                        let did = id.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_secs(
                                                PAIRING_TIMEOUT_SECS,
                                            ))
                                            .await;
                                            if let Some(dev) = dm.get_device(&did).await
                                                && dev.pair_state
                                                    == crate::device::PairState::Requested
                                            {
                                                info!(
                                                    "[core] incoming pair request from {} timed out after {}s",
                                                    did, PAIRING_TIMEOUT_SECS
                                                );
                                                let pair = Pair::reject();
                                                let value = serde_json::to_value(pair)
                                                    .expect("fail serializing pair");
                                                let pkt =
                                                    ProtocolPacket::new(PacketType::Pair, value);
                                                let _ = event_tx.send(CoreEvent::SendPacket {
                                                    device: did.clone(),
                                                    packet: pkt,
                                                });
                                                dm.update_pair_state(
                                                    &did,
                                                    crate::device::PairState::NotPaired,
                                                )
                                                .await;
                                                let ev = ConnectionEvent::PairingTimedOut(did);
                                                let _ = conn_tx.send(ev.clone());
                                                let _ = mpris_tx.send(ev);
                                            }
                                        });
                                    }
                                }
                            }
                        } else if matches!(pkt.packet_type, PacketType::Identity) {
                            debug!("[core] identity packet from {}; ignoring in event loop", id);
                        } else if self
                            .device_manager
                            .get_device(&id)
                            .await
                            .map(|device| device.pair_state == crate::device::PairState::Paired)
                            .unwrap_or(false)
                        {
                            let _ = self.event_tx.send(CoreEvent::PacketReceived {
                                device: id.clone(),
                                packet: pkt.clone(),
                            });
                        } else {
                            self.reject_unpaired_packet(&id, pkt.packet_type).await;
                        }
                    }
                    Err(e) => {
                        let _ = self.event_tx.send(CoreEvent::Error(format!(
                            "Invalid packet from {}: {}",
                            addr, e
                        )));
                    }
                }
            }
            TransportEvent::Disconnected { id, conn_id } => {
                // Check whether this disconnect belongs to the connection that is
                // currently live for this device. If conn_id_map holds a *different*
                // (higher) ID, a newer connection has already taken over and this
                // event is stale — dropping it avoids wiping the live writer entry.
                let is_current = { is_current_connection(&self.conn_id_map, &id, conn_id).await };

                if !is_current {
                    info!(
                        "[core] stale Disconnected for {} (conn_id {} != current) — ignoring",
                        id, conn_id
                    );
                    return;
                }

                self.fail_pairing_if_pending(&id, "connection dropped")
                    .await;
                remove_connection_if_current(&self.writer_map, &self.conn_id_map, &id, conn_id)
                    .await;
                plugins::systemvolume::on_device_disconnect(&id);
                self.broadcast_on_disconnect(&id).await;
                info!("[core] removed dead connection for {}", id);
                let conn_event = ConnectionEvent::Disconnected(id);
                let _ = self.conn_tx.send(conn_event.clone());
                let _ = self.mpris_conn_tx.send(conn_event);
            }
            TransportEvent::PacketSendFailed {
                id,
                packet_type,
                conn_id,
            } => {
                if !self.is_current_connection(&id, conn_id).await {
                    info!(
                        "[core] stale send failure for {} (conn_id {} != current) — ignoring",
                        id, conn_id
                    );
                    return;
                }
                warn!(
                    "[core] failed to send {:?} to {}; removing broken connection",
                    packet_type, id
                );
                if matches!(packet_type, PacketType::Pair) {
                    self.fail_pairing_if_pending(&id, "pair packet send failed")
                        .await;
                }
                if remove_connection_if_current(&self.writer_map, &self.conn_id_map, &id, conn_id)
                    .await
                {
                    plugins::systemvolume::on_device_disconnect(&id);
                    self.broadcast_on_disconnect(&id).await;
                    let conn_event = ConnectionEvent::Disconnected(id);
                    let _ = self.conn_tx.send(conn_event.clone());
                    let _ = self.mpris_conn_tx.send(conn_event);
                }
            }
            TransportEvent::PairTrustFailed { id } => {
                warn!(
                    "[core] certificate trust failed for paired device {}; unpairing",
                    id
                );
                if let Some(mut device) = self.device_manager.get_device(&id).await {
                    device.remote_certificate.clear();
                    self.device_manager
                        .add_or_update_device(id.clone(), device)
                        .await;
                }
                self.device_manager
                    .update_pair_state(&id, crate::device::PairState::NotPaired)
                    .await;
                cleanup_device_data(&id.0).await;
            }
        }
    }

    pub(crate) async fn kde_events(&self, event: AppEvent) {
        match event {
            AppEvent::Broadcasting => {
                let _ = self.udp_transport.send_identity().await;
            }
            AppEvent::Pair(device_id) => {
                info!("frontend sent pair event to device: {}", device_id);

                let current_state = match self.device_manager.get_device(&device_id).await {
                    Some(device) => device.pair_state,
                    None => {
                        warn!("[core] cannot pair unknown device {}", device_id);
                        let _ = self.udp_transport.send_identity().await;
                        let ev = ConnectionEvent::PairingTimedOut(device_id);
                        let _ = self.conn_tx.send(ev.clone());
                        let _ = self.mpris_conn_tx.send(ev);
                        return;
                    }
                };

                match current_state {
                    crate::device::PairState::Paired => {
                        warn!(
                            "[core] ignoring pair request for already paired device {}",
                            device_id
                        );
                        let conn_event = ConnectionEvent::PairStateChanged((
                            device_id,
                            crate::device::PairState::Paired,
                        ));
                        let _ = self.conn_tx.send(conn_event.clone());
                        let _ = self.mpris_conn_tx.send(conn_event);
                        return;
                    }
                    crate::device::PairState::Requested => {
                        info!(
                            "[core] pair requested while peer request is pending; accepting {}",
                            device_id
                        );
                        let pair = Pair::accept();
                        let value = serde_json::to_value(pair).expect("fail serializing pair");
                        let pkt = ProtocolPacket::new(PacketType::Pair, value);
                        if self.queue_packet(&device_id, pkt).await {
                            self.device_manager.set_paired(&device_id, true).await;
                        } else {
                            warn!(
                                "[core] failed to accept pending pair request from {}",
                                device_id
                            );
                            self.device_manager
                                .update_pair_state(&device_id, crate::device::PairState::NotPaired)
                                .await;
                            let ev = ConnectionEvent::PairingTimedOut(device_id);
                            let _ = self.conn_tx.send(ev.clone());
                            let _ = self.mpris_conn_tx.send(ev);
                        }
                        return;
                    }
                    crate::device::PairState::Requesting => {
                        warn!(
                            "[core] restarting stale or in-progress pair request for {}",
                            device_id
                        );
                    }
                    crate::device::PairState::NotPaired => {}
                }

                let pair = Pair::request();
                if let Some(timestamp) = pair.timestamp {
                    self.device_manager
                        .set_pairing_timestamp(&device_id, timestamp)
                        .await;
                }
                let value = serde_json::to_value(pair).expect("fail serializing pair");
                let pkt = ProtocolPacket::new(PacketType::Pair, value);

                let udp = self.udp_transport.clone();
                let wm = self.writer_map.clone();
                let dm = self.device_manager.clone();
                let event_tx2 = self.event_tx.clone();
                let conn_tx2 = self.conn_tx.clone();
                let mpris_tx2 = self.mpris_conn_tx.clone();
                let did = device_id.clone();
                let pkt_clone = pkt.clone();

                let queued = self.queue_packet(&device_id, pkt).await;
                if queued {
                    info!("Sent pair request packet to device: {}", device_id);
                } else {
                    warn!(
                        "[core] failed to send pair request to {} (no active connection); reconnecting before retry",
                        device_id
                    );
                    let _ = self.udp_transport.send_identity().await;
                }

                let attempt_id = {
                    let mut attempts = self.pairing_attempts.lock().await;
                    let next = attempts
                        .get(&device_id)
                        .copied()
                        .unwrap_or(0)
                        .wrapping_add(1);
                    attempts.insert(device_id.clone(), next);
                    next
                };

                self.device_manager
                    .update_pair_state(&device_id, crate::device::PairState::Requesting)
                    .await;

                let attempts = self.pairing_attempts.clone();
                let initially_queued = queued;
                tokio::spawn(async move {
                    let mut retried = false;

                    if initially_queued {
                        tokio::time::sleep(Duration::from_secs(PAIRING_TIMEOUT_SECS)).await;

                        if attempts.lock().await.get(&did).copied() != Some(attempt_id) {
                            return;
                        }

                        if let Some(dev) = dm.get_device(&did).await
                            && dev.pair_state != crate::device::PairState::Requesting
                        {
                            attempts.lock().await.remove(&did);
                            return;
                        }

                        info!(
                            "[core] pair request to {} timed out after {}s — attempting reconnect",
                            did, PAIRING_TIMEOUT_SECS
                        );

                        let _ = udp.send_identity().await;
                    }

                    for _ in 0..30 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let sender = wm
                            .lock()
                            .await
                            .get(&did)
                            .map(|handle| handle.write_tx.clone());
                        if let Some(sender) = sender
                            && sender.send(pkt_clone.clone()).is_ok()
                        {
                            info!("[core] pair request sent to {} after reconnect", did);
                            retried = true;
                            break;
                        }
                    }

                    if retried {
                        tokio::time::sleep(Duration::from_secs(PAIRING_TIMEOUT_SECS)).await;
                    }

                    if attempts.lock().await.get(&did).copied() != Some(attempt_id) {
                        return;
                    }

                    if let Some(dev) = dm.get_device(&did).await
                        && dev.pair_state == crate::device::PairState::Requesting
                    {
                        info!("[core] pairing with {} timed out definitively", did);
                        let pair = Pair::reject();
                        let value = serde_json::to_value(pair).expect("fail serializing pair");
                        let pkt = ProtocolPacket::new(PacketType::Pair, value);
                        let _ = event_tx2.send(CoreEvent::SendPacket {
                            device: did.clone(),
                            packet: pkt,
                        });
                        dm.update_pair_state(&did, crate::device::PairState::NotPaired)
                            .await;
                        attempts.lock().await.remove(&did);
                        let ev = ConnectionEvent::PairingTimedOut(did);
                        let _ = conn_tx2.send(ev.clone());
                        let _ = mpris_tx2.send(ev);
                    }
                });
            }
            AppEvent::Ping((device_id, msg)) => {
                info!("frontend sent ping event to device: {}", device_id);
                let value = serde_json::to_value(Ping {
                    message: Some(msg),
                    ..Default::default()
                })
                .expect("fail serializing packet body");
                let pkt = ProtocolPacket::new(PacketType::Ping, value);
                let _ = self.queue_packet(&device_id, pkt).await;
            }
            AppEvent::SendPacket(device_id, packet) => {
                info!("Sending packet to device: {}", device_id);
                let _ = self.queue_packet(&device_id, packet).await;
            }
            AppEvent::SendFiles((device_id, files_list)) => {
                info!("frontend trying to sent files to device: {}", device_id);

                if !self
                    .packet_allowed_to_send(&device_id, &PacketType::ShareRequest)
                    .await
                {
                    warn!(
                        "[core] dropping file send for {} because device is not paired",
                        device_id
                    );
                    return;
                }

                let sender = {
                    let guard = self.writer_map.lock().await;
                    guard.get(&device_id).map(|handle| handle.write_tx.clone())
                };

                if let Some(sender) = sender {
                    debug!("sender available.");
                    let pkts = match ShareRequest::share_files(files_list).await {
                        Ok(pkts) => pkts,
                        Err(e) => {
                            tracing::warn!("[share] failed to prepare share request: {}", e);
                            return;
                        }
                    };
                    for (pkt_body, path) in pkts {
                        let packet = ProtocolPacket::new(
                            PacketType::ShareRequest,
                            serde_json::to_value(pkt_body).expect("serializing packet body"),
                        );
                        let file = match DeviceFile::open(&path).await {
                            Ok(file) => file,
                            Err(e) => {
                                tracing::warn!("[share] failed to open '{}': {}", path, e);
                                continue;
                            }
                        };
                        let payload = DevicePayload::from(file);

                        let transfer_adapter =
                            TransferAdapter::new(payload.buf, payload.size, self.conn_tx.clone());

                        self.plugin_registry
                            .send_payload(packet, &sender, transfer_adapter, payload.size)
                            .await;
                    }

                    debug!("file transfer tasks spawned.");
                }
            }
            AppEvent::MprisAction((device_id, player_name, action)) => {
                info!(
                    "frontend sent mpris action to device: {} player: {}",
                    device_id, player_name
                );
                let request = crate::plugins::mpris::MprisRequest {
                    player: Some(player_name),
                    request_now_playing: None,
                    request_player_list: None,
                    request_volume: None,
                    seek: None,
                    set_loop_status: None,
                    set_position: None,
                    set_shuffle: None,
                    set_volume: None,
                    action: Some(action),
                    album_art_url: None,
                };
                let value = serde_json::to_value(request).expect("fail serializing packet body");
                let pkt = ProtocolPacket::new(PacketType::MprisRequest, value);
                if let Some(device) = self.device_manager.get_device(&device_id).await {
                    self.plugin_registry
                        .send(device.clone(), pkt, self.event_tx.clone())
                        .await;
                };
            }
            AppEvent::SendMprisRequest((device_id, request)) => {
                info!("frontend sent mpris request to device: {}", device_id);
                let value = serde_json::to_value(request).expect("fail serializing packet body");
                let pkt = ProtocolPacket::new(PacketType::MprisRequest, value);
                if let Some(device) = self.device_manager.get_device(&device_id).await {
                    self.plugin_registry
                        .send(device.clone(), pkt, self.event_tx.clone())
                        .await;
                };
            }
            AppEvent::Unpair(device_id) => {
                info!("frontend sent unpair event to device: {}", device_id);

                remove_pairing_attempt(&self.pairing_attempts, &device_id).await;
                self.device_manager
                    .update_pair_state(&device_id, crate::device::PairState::NotPaired)
                    .await;

                let pkt = pair_false_packet();
                let queued = self.queue_packet(&device_id, pkt).await;

                let writer_map = self.writer_map.clone();
                let conn_id_map = self.conn_id_map.clone();
                tokio::spawn(async move {
                    if queued {
                        info!("[core] sent pair:false to {} on unpair", device_id);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    cleanup_device_data(&device_id.0).await;
                    if remove_connection(&writer_map, &conn_id_map, &device_id).await {
                        plugins::systemvolume::on_device_disconnect(&device_id);
                        info!("[core] dropped connection for {}", device_id);
                    }
                });
            }
            AppEvent::AcceptPairing(device_id) => {
                info!("User accepted pairing from {}", device_id);

                let Some(dev) = self.device_manager.get_device(&device_id).await else {
                    warn!("[core] ignoring accept for unknown device {}", device_id);
                    let ev = ConnectionEvent::PairingTimedOut(device_id);
                    let _ = self.conn_tx.send(ev.clone());
                    let _ = self.mpris_conn_tx.send(ev);
                    return;
                };

                if dev.pair_state != crate::device::PairState::Requested {
                    warn!(
                        "[core] ignoring stale pair accept for {} in state {:?}",
                        device_id, dev.pair_state
                    );
                    let ev = ConnectionEvent::PairingTimedOut(device_id);
                    let _ = self.conn_tx.send(ev.clone());
                    let _ = self.mpris_conn_tx.send(ev);
                    return;
                }

                // Clock-sync validation per KDE Connect protocol v8+:
                // if the phone's pairing timestamp and our current time differ
                // by more than 30 minutes, reject the pairing to prevent
                // security issues from clock skew.
                if dev.protocol_version >= 8 {
                    let phone_ts = dev.pairing_timestamp;
                    if phone_ts > 0 {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let diff = phone_ts.abs_diff(now);
                        if diff > ALLOWED_TIMESTAMP_DIFF_SECS {
                            warn!(
                                "[core] pairing rejected for {}: clocks out of sync (phone_ts={}, local_ts={}, diff={}s)",
                                device_id, phone_ts, now, diff
                            );
                            // Reject by sending pair:false and un-setting paired state.
                            let pair = Pair::reject();
                            let value = serde_json::to_value(pair).expect("fail serializing pair");
                            let pkt = ProtocolPacket::new(PacketType::Pair, value);
                            if self.queue_packet(&device_id, pkt).await {
                                info!(
                                    "[core] sent pair:false to {} due to clock mismatch",
                                    device_id
                                );
                            }
                            self.device_manager
                                .update_pair_state(&device_id, crate::device::PairState::NotPaired)
                                .await;
                            // Emit a timed-out event so the UI can show a message.
                            let ev = ConnectionEvent::PairingTimedOut(device_id);
                            let _ = self.conn_tx.send(ev.clone());
                            let _ = self.mpris_conn_tx.send(ev);
                            return;
                        }
                    }
                }

                let pair = Pair::accept();
                let value = serde_json::to_value(pair).expect("fail serializing pair");
                let pkt = ProtocolPacket::new(PacketType::Pair, value);
                if self.queue_packet(&device_id, pkt).await {
                    info!("[core] sent pair:true to {} on accept", device_id);
                    self.device_manager.set_paired(&device_id, true).await;
                } else {
                    warn!(
                        "[core] failed to send pair acceptance to {} (no connection)",
                        device_id
                    );
                    self.device_manager
                        .update_pair_state(&device_id, crate::device::PairState::NotPaired)
                        .await;
                    let ev = ConnectionEvent::PairingTimedOut(device_id);
                    let _ = self.conn_tx.send(ev.clone());
                    let _ = self.mpris_conn_tx.send(ev);
                }
            }
            AppEvent::RejectPairing(device_id) => {
                info!("User rejected pairing from {}", device_id);

                let Some(dev) = self.device_manager.get_device(&device_id).await else {
                    warn!("[core] ignoring reject for unknown device {}", device_id);
                    let ev = ConnectionEvent::PairingTimedOut(device_id);
                    let _ = self.conn_tx.send(ev.clone());
                    let _ = self.mpris_conn_tx.send(ev);
                    return;
                };

                if dev.pair_state != crate::device::PairState::Requested {
                    warn!(
                        "[core] ignoring stale pair reject for {} in state {:?}",
                        device_id, dev.pair_state
                    );
                    let ev = ConnectionEvent::PairingTimedOut(device_id);
                    let _ = self.conn_tx.send(ev.clone());
                    let _ = self.mpris_conn_tx.send(ev);
                    return;
                }

                let pair = Pair::reject();
                let value = serde_json::to_value(pair).expect("fail serializing pair");
                let pkt = ProtocolPacket::new(PacketType::Pair, value);
                if self.queue_packet(&device_id, pkt).await {
                    info!("[core] sent pair:false to {} on reject", device_id);
                }
                self.device_manager
                    .update_pair_state(&device_id, crate::device::PairState::NotPaired)
                    .await;
            }
            AppEvent::Disconnect(device_id) => {
                info!("frontend sent disconnect event to device: {}", device_id);
                if self.drop_connection(&device_id).await {
                    let conn_event = ConnectionEvent::Disconnected(device_id);
                    let _ = self.conn_tx.send(conn_event.clone());
                    let _ = self.mpris_conn_tx.send(conn_event);
                    info!("Connection closed.");
                }
            }
            AppEvent::SetPluginEnabled {
                device_id,
                plugin_id,
                enabled,
            } => {
                info!(
                    "[plugin] {} plugin '{}' for device {}",
                    if enabled { "enabling" } else { "disabling" },
                    plugin_id,
                    device_id
                );
                let mut disabled: std::collections::HashSet<String> =
                    plugin_config::load_disabled_plugins(&device_id.0).await;
                if enabled {
                    disabled.remove(&plugin_id);
                } else {
                    disabled.insert(plugin_id.clone());
                }
                plugin_config::save_disabled_plugins(&device_id.0, &disabled).await;
                self.plugin_registry
                    .set_device_disabled(&device_id.0, disabled.clone())
                    .await;

                if self.drop_connection(&device_id).await {
                    info!(
                        "[plugin] dropped connection to {} — phone will reconnect with updated capabilities",
                        device_id
                    );
                }
            }
        };
    }

    async fn packet_allowed_to_send(&self, device_id: &DeviceId, packet_type: &PacketType) -> bool {
        let pair_state = self
            .device_manager
            .get_device(device_id)
            .await
            .map(|device| device.pair_state);

        packet_allowed_for_pair_state(packet_type, pair_state)
    }

    fn schedule_connection_drop(&self, device_id: DeviceId, delay: Duration) {
        let writer_map = self.writer_map.clone();
        let conn_id_map = self.conn_id_map.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            remove_connection(&writer_map, &conn_id_map, &device_id).await;
        });
    }

    async fn reject_unpaired_packet(&self, device_id: &DeviceId, packet_type: PacketType) {
        warn!(
            "[core] received {:?} from unpaired device {}; rejecting stale traffic and dropping connection",
            packet_type, device_id
        );

        remove_pairing_attempt(&self.pairing_attempts, device_id).await;
        if self
            .device_manager
            .get_device(device_id)
            .await
            .map(|device| device.pair_state != PairState::NotPaired)
            .unwrap_or(false)
        {
            self.device_manager
                .update_pair_state(device_id, PairState::NotPaired)
                .await;
        }
        plugins::systemvolume::on_device_disconnect(device_id);

        if self.unpaired_resync_limiter.should_send(device_id).await {
            if self.queue_packet(device_id, pair_false_packet()).await {
                info!(
                    "[core] sent pair:false to {} after unpaired {:?}",
                    device_id, packet_type
                );
                self.schedule_connection_drop(device_id.clone(), UNPAIRED_RESYNC_DROP_DELAY);
                return;
            }
        } else {
            debug!(
                "[core] throttled duplicate pair:false resync for {} after {:?}",
                device_id, packet_type
            );
        }

        self.drop_connection(device_id).await;
    }

    async fn queue_packet(&self, device_id: &DeviceId, packet: ProtocolPacket) -> bool {
        if !self
            .packet_allowed_to_send(device_id, &packet.packet_type)
            .await
        {
            warn!(
                "[core] dropping outbound {:?} for {} because device is not paired",
                packet.packet_type, device_id
            );
            return false;
        }

        let sender = {
            let guard = self.writer_map.lock().await;
            let sender = guard.get(device_id).map(|handle| handle.write_tx.clone());
            if sender.is_none() {
                debug!(
                    "No sender for device {} — available: {:?}",
                    device_id,
                    guard.keys().collect::<Vec<_>>()
                );
            }
            sender
        };

        let Some(sender) = sender else {
            return false;
        };

        if let Err(e) = sender.send(packet) {
            tracing::warn!(
                "[core] failed to queue packet for {}: {}; removing stale writer",
                device_id,
                e
            );
            remove_connection(&self.writer_map, &self.conn_id_map, device_id).await;
            plugins::systemvolume::on_device_disconnect(device_id);
            self.broadcast_on_disconnect(device_id).await;
            let conn_event = ConnectionEvent::Disconnected(device_id.clone());
            let _ = self.conn_tx.send(conn_event.clone());
            let _ = self.mpris_conn_tx.send(conn_event);
            return false;
        }

        true
    }

    async fn broadcast_on_disconnect(&self, device_id: &DeviceId) {
        if let Some(device) = self.device_manager.get_device(device_id).await {
            if device.pair_state == PairState::Paired {
                debug!(
                    "[core] broadcasting identity after disconnect of {}",
                    device_id
                );
                if let Err(e) = self.udp_transport.send_identity().await {
                    error!("Identity broadcast after disconnect failed: {}", e);
                }
            }
        }
    }

    async fn drop_connection(&self, device_id: &DeviceId) -> bool {
        if remove_connection(&self.writer_map, &self.conn_id_map, device_id).await {
            plugins::systemvolume::on_device_disconnect(device_id);
            info!("[core] dropped connection for {}", device_id);
            true
        } else {
            false
        }
    }

    async fn is_current_connection(&self, device_id: &DeviceId, conn_id: u64) -> bool {
        is_current_connection(&self.conn_id_map, device_id, conn_id).await
    }

    async fn fail_pairing_if_pending(&self, device_id: &DeviceId, reason: &str) {
        let Some(device) = self.device_manager.get_device(device_id).await else {
            return;
        };

        if !matches!(
            device.pair_state,
            PairState::Requesting | PairState::Requested
        ) {
            return;
        }

        warn!(
            "[core] pairing with {} failed while in {:?}: {}",
            device_id, device.pair_state, reason
        );
        remove_pairing_attempt(&self.pairing_attempts, device_id).await;
        self.device_manager
            .update_pair_state(device_id, PairState::NotPaired)
            .await;
        let ev = ConnectionEvent::PairingTimedOut(device_id.clone());
        let _ = self.conn_tx.send(ev.clone());
        let _ = self.mpris_conn_tx.send(ev);
    }

    pub fn take_events(&self) -> Arc<mpsc::UnboundedSender<AppEvent>> {
        self.out_tx.clone()
    }
}
