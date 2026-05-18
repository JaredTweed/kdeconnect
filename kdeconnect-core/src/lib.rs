use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    select,
    sync::{Mutex, mpsc, watch},
    time::MissedTickBehavior,
};
use tracing::{debug, error, info, warn};

use crate::{
    core::connection::{
        ConnectionHandle, UnpairedResyncLimiter,
    },
    device::{Device, DeviceId, DeviceManager, PairState},
    event::{AppEvent, ConnectionEvent, CoreEvent},
    pairing::PairingManager,
    plugin_interface::PluginRegistry,
    protocol::Pair,
    transport::{ConnectionRateLimiter, TcpTransport, TransportEvent, UdpTransport},
};

pub(crate) mod core;

pub mod config;
pub(crate) mod crypto;
pub mod device;
pub mod event;
pub mod filetransfer;
pub(crate) mod pairing;
pub mod plugin_config;
pub(crate) mod plugin_interface;
pub mod plugins;
pub(crate) mod protocol;
pub(crate) mod transport;

pub use protocol::{PacketType, ProtocolPacket};

pub static GLOBAL_CONFIG: OnceLock<config::Config> = OnceLock::new();

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: once_cell::sync::Lazy<Mutex<()>> =
    once_cell::sync::Lazy::new(|| Mutex::new(()));

pub struct KdeConnectCore {
    device_manager: Arc<DeviceManager>,
    pairing: Arc<PairingManager>,
    plugin_registry: Arc<PluginRegistry>,
    transport_rx: mpsc::UnboundedReceiver<TransportEvent>,
    writer_map: Arc<Mutex<HashMap<DeviceId, ConnectionHandle>>>,
    conn_id_map: Arc<Mutex<HashMap<DeviceId, u64>>>,
    pairing_attempts: Arc<Mutex<HashMap<DeviceId, u64>>>,
    unpaired_resync_limiter: Arc<UnpairedResyncLimiter>,
    event_tx: mpsc::UnboundedSender<CoreEvent>,
    event_rx: mpsc::UnboundedReceiver<CoreEvent>,
    udp_transport: Arc<UdpTransport>,
    out_tx: Arc<mpsc::UnboundedSender<AppEvent>>,
    in_rx: mpsc::UnboundedReceiver<AppEvent>,
    conn_tx: mpsc::UnboundedSender<ConnectionEvent>,
    mpris_conn_tx: mpsc::UnboundedSender<ConnectionEvent>,
}

impl KdeConnectCore {
    pub async fn new() -> anyhow::Result<(Self, mpsc::UnboundedReceiver<ConnectionEvent>)> {
        let (out_tx, in_rx) = mpsc::unbounded_channel();
        let (conn_tx, conn_rx) = mpsc::unbounded_channel();
        let (mpris_conn_tx, mpris_conn_rx) = mpsc::unbounded_channel();

        let plugin_registry = Arc::new(PluginRegistry::new());

        let outgoing_capabilities = plugin_registry.list_plugins().await;
        let config = config::Config::load(outgoing_capabilities).await?;

        GLOBAL_CONFIG
            .set(config)
            .expect("Config already initialized");

        let (transport_tx, transport_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let pairing_attempts = Arc::new(Mutex::new(HashMap::new()));
        let unpaired_resync_limiter = Arc::new(UnpairedResyncLimiter::default());

        let device_manager = DeviceManager::new(event_tx.clone());
        let pairing = Arc::new(PairingManager::new(device_manager.clone()));

        let connection_rate_limiter = Arc::new(ConnectionRateLimiter::default());
        let tcp_transport = TcpTransport::new(&transport_tx, connection_rate_limiter.clone());
        let udp_transport =
            Arc::new(UdpTransport::new(&transport_tx, connection_rate_limiter).await);

        tokio::spawn(async move {
            if let Err(e) = tcp_transport.listen().await {
                tracing::error!("TCP listener failed: {}", e);
            }
        });

        let udp = Arc::clone(&udp_transport);
        tokio::spawn(async move {
            if let Err(e) = udp.listen().await {
                error!("UDP listener failed: {}", e);
            }
        });

        if let Some(config_dir) = dirs::config_dir() {
            let kc_dir = config_dir.join(config::CONFIG_DIR);
            if let Ok(mut entries) = tokio::fs::read_dir(&kc_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("ron") {
                        match tokio::fs::read_to_string(&path).await {
                            Ok(raw) => {
                                if let Ok(dev) = ron::de::from_str::<Device>(&raw)
                                    && dev.pair_state == PairState::Paired
                                {
                                    info!("Loaded paired device from disk: {}", dev.device_id);
                                    device_manager
                                        .add_or_update_device(dev.device_id.clone(), dev)
                                        .await;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to read persisted device file: {}", e);
                            }
                        }
                    }
                }
            }
        }

        let udp_broadcast = Arc::clone(&udp_transport);
        tokio::spawn(async move {
            if let Err(e) = udp_broadcast.send_identity().await {
                warn!("[core] initial identity broadcast failed: {}", e);
            }
        });

        let reconnect_udp = Arc::clone(&udp_transport);
        let reconnect_dm = device_manager.clone();
        let reconnect_wm = Arc::clone(&writer_map);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let has_disconnected_paired = {
                    let devices = reconnect_dm.get_devices().await;
                    let writers = reconnect_wm.lock().await;
                    devices.iter().any(|d| {
                        d.pair_state == PairState::Paired && !writers.contains_key(&d.device_id)
                    })
                };
                if has_disconnected_paired {
                    debug!(
                        "Reconnect timer: broadcasting identity for disconnected paired devices"
                    );
                    if let Err(e) = reconnect_udp.send_identity().await {
                        error!("Reconnect broadcast failed: {}", e);
                    }
                }
            }
        });

        let run_command_plugin = plugins::run_command::RunCommandRequest::default();
        plugin_registry.register(Arc::new(run_command_plugin)).await;
        let share_request_plugin = plugins::share::ShareRequest::default();
        plugin_registry
            .register(Arc::new(share_request_plugin))
            .await;
        let sms_plugin = plugins::sms::SmsMessages {
            messages: Vec::new(),
            version: None,
            device_id: None,
        };
        plugin_registry.register(Arc::new(sms_plugin)).await;

        plugins::mpris::init_telephony_signal();
        plugins::mpris::expose_phone_mpris(mpris_conn_rx, event_tx.clone());

        Ok((
            Self {
                device_manager: Arc::new(device_manager),
                pairing,
                plugin_registry,
                transport_rx,
                writer_map,
                conn_id_map,
                pairing_attempts,
                unpaired_resync_limiter,
                event_tx,
                event_rx,
                udp_transport,
                out_tx: Arc::new(out_tx),
                in_rx,
                conn_tx,
                mpris_conn_tx,
            },
            conn_rx,
        ))
    }

    pub async fn run_event_loop(&mut self) {
        loop {
            select! {
                maybe_event = self.event_rx.recv() => {
                    match maybe_event {
                        Some(event) => self.core_events(event).await,
                        None => {
                            error!("CoreEvent channel closed — aborting event loop");
                            break;
                        }
                    }
                }
                maybe_event = self.transport_rx.recv() => {
                    match maybe_event {
                        Some(event) => self.transport_events(event).await,
                        None => {
                            error!("Transport channel closed — aborting event loop");
                            break;
                        }
                    }
                }
                maybe_kde = self.in_rx.recv() => {
                    match maybe_kde {
                        Some(event) => self.kde_events(event).await,
                        None => {
                            error!("KdeEvent channel closed — aborting event loop");
                            break;
                        }
                    }
                }
            }
        }
    }
}

pub async fn cleanup_device_data(device_id: &str) {
    if let Some(config_dir) = dirs::config_dir() {
        let kc_config = config_dir.join(config::CONFIG_DIR);
        let mut dir = match tokio::fs::read_dir(&kc_config).await {
            Ok(dir) => dir,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                && stem.starts_with(device_id)
            {
                let _ = tokio::fs::remove_file(&path).await;
                tracing::debug!("[cleanup] removed config file: {}", path.display());
            }
        }
    }

    if let Some(local_share) = dirs::data_local_dir() {
        let kc_cache = local_share.join(config::CONFIG_DIR);
        let mut dir = match tokio::fs::read_dir(&kc_cache).await {
            Ok(dir) => dir,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                && (stem.starts_with(device_id) || stem == device_id)
            {
                if path.is_dir() {
                    let _ = tokio::fs::remove_dir_all(&path).await;
                    tracing::debug!("[cleanup] removed cache dir: {}", path.display());
                } else {
                    let _ = tokio::fs::remove_file(&path).await;
                    tracing::debug!("[cleanup] removed cache file: {}", path.display());
                }
            }
        }
    }

    tracing::info!("[cleanup] removed persisted data for device {}", device_id);
}

#[cfg(test)]
mod pairing_regression_tests {
    use super::*;
    use crate::core::connection::{
        ConnectionHandle, UNPAIRED_RESYNC_INTERVAL, UnpairedResyncLimiter, install_connection,
        is_current_connection, packet_allowed_for_pair_state, pair_false_packet, remove_connection,
        remove_connection_if_current, remove_pairing_attempt,
    };
    use serde_json::json;
    use tokio::time::timeout;

    fn test_device_id(suffix: &str) -> DeviceId {
        DeviceId(format!("pairing-regression-{suffix}"))
    }

    fn test_connection_handle() -> (
        ConnectionHandle,
        watch::Receiver<bool>,
        mpsc::UnboundedReceiver<ProtocolPacket>,
    ) {
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        (
            ConnectionHandle {
                write_tx,
                shutdown_tx,
            },
            shutdown_rx,
            write_rx,
        )
    }

    #[tokio::test]
    async fn replacing_device_connection_shuts_down_only_the_previous_link() {
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let device_id = test_device_id("replace-one");

        let (first, mut first_shutdown, _first_rx) = test_connection_handle();
        let (second, second_shutdown, mut second_rx) = test_connection_handle();

        install_connection(&writer_map, &conn_id_map, device_id.clone(), 1, first).await;
        install_connection(&writer_map, &conn_id_map, device_id.clone(), 2, second).await;

        first_shutdown.changed().await.unwrap();
        assert!(*first_shutdown.borrow());
        assert!(!*second_shutdown.borrow());
        assert!(is_current_connection(&conn_id_map, &device_id, 2).await);
        assert!(!is_current_connection(&conn_id_map, &device_id, 1).await);

        let sender = writer_map
            .lock()
            .await
            .get(&device_id)
            .unwrap()
            .write_tx
            .clone();
        let pkt = ProtocolPacket::new(PacketType::Ping, json!({}));
        sender.send(pkt).unwrap();
        assert!(matches!(
            second_rx.recv().await.unwrap().packet_type,
            PacketType::Ping
        ));
    }

    #[tokio::test]
    async fn stale_disconnect_cannot_remove_newer_connection() {
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let device_id = test_device_id("stale-disconnect");

        let (first, mut first_shutdown, _first_rx) = test_connection_handle();
        let (second, mut second_shutdown, _second_rx) = test_connection_handle();

        install_connection(&writer_map, &conn_id_map, device_id.clone(), 10, first).await;
        install_connection(&writer_map, &conn_id_map, device_id.clone(), 11, second).await;
        first_shutdown.changed().await.unwrap();

        assert!(!remove_connection_if_current(&writer_map, &conn_id_map, &device_id, 10).await);
        assert!(writer_map.lock().await.contains_key(&device_id));
        assert!(!*second_shutdown.borrow());
        assert!(
            timeout(Duration::from_millis(25), second_shutdown.changed())
                .await
                .is_err()
        );
        assert!(is_current_connection(&conn_id_map, &device_id, 11).await);
    }

    #[tokio::test]
    async fn dropping_connection_shuts_down_only_that_device() {
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let first_id = test_device_id("drop-first");
        let second_id = test_device_id("drop-second");

        let (first, mut first_shutdown, _first_rx) = test_connection_handle();
        let (second, second_shutdown, _second_rx) = test_connection_handle();

        install_connection(&writer_map, &conn_id_map, first_id.clone(), 1, first).await;
        install_connection(&writer_map, &conn_id_map, second_id.clone(), 1, second).await;

        assert!(remove_connection(&writer_map, &conn_id_map, &first_id).await);
        first_shutdown.changed().await.unwrap();
        assert!(*first_shutdown.borrow());
        assert!(!writer_map.lock().await.contains_key(&first_id));
        assert!(!is_current_connection(&conn_id_map, &first_id, 1).await);

        assert!(writer_map.lock().await.contains_key(&second_id));
        assert!(is_current_connection(&conn_id_map, &second_id, 1).await);
        assert!(!*second_shutdown.borrow());
    }

    #[tokio::test]
    async fn repeated_reconnect_churn_is_isolated_across_devices() {
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let ids = vec![
            test_device_id("churn-a"),
            test_device_id("churn-b"),
            test_device_id("churn-c"),
        ];
        let mut tasks = Vec::new();
        for id in ids.clone() {
            let writer_map = writer_map.clone();
            let conn_id_map = conn_id_map.clone();
            tasks.push(tokio::spawn(async move {
                for conn_id in 0..25 {
                    let (handle, _shutdown, _rx) = test_connection_handle();
                    install_connection(&writer_map, &conn_id_map, id.clone(), conn_id, handle)
                        .await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let writers = writer_map.lock().await;
        assert_eq!(writers.len(), ids.len());
        drop(writers);
        for id in ids {
            assert!(is_current_connection(&conn_id_map, &id, 24).await);
        }
    }

    #[tokio::test]
    async fn concurrent_replacements_keep_writer_and_conn_id_in_sync() {
        let writer_map = Arc::new(Mutex::new(HashMap::new()));
        let conn_id_map = Arc::new(Mutex::new(HashMap::new()));
        let device_id = test_device_id("same-device-race");
        let mut receivers = HashMap::new();
        let mut shutdowns = HashMap::new();
        let mut tasks = Vec::new();
        for conn_id in 0..50 {
            let (handle, shutdown_rx, rx) = test_connection_handle();
            receivers.insert(conn_id, rx);
            shutdowns.insert(conn_id, shutdown_rx);
            let writer_map = writer_map.clone();
            let conn_id_map = conn_id_map.clone();
            let id = device_id.clone();
            tasks.push(tokio::spawn(async move {
                install_connection(&writer_map, &conn_id_map, id, conn_id, handle).await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let current_conn_id = conn_id_map
            .lock()
            .await
            .get(&device_id)
            .copied()
            .expect("missing current conn_id");
        let sender = writer_map
            .lock()
            .await
            .get(&device_id)
            .expect("missing current writer")
            .write_tx
            .clone();
        sender
            .send(ProtocolPacket::new(PacketType::Ping, json!({})))
            .unwrap();
        let current_rx = receivers
            .get_mut(&current_conn_id)
            .expect("missing current receiver");
        assert!(matches!(
            timeout(Duration::from_secs(1), current_rx.recv()).await,
            Ok(Some(packet)) if matches!(packet.packet_type, PacketType::Ping)
        ));
        for (conn_id, mut shutdown_rx) in shutdowns {
            if conn_id == current_conn_id {
                assert!(!*shutdown_rx.borrow());
            } else if !*shutdown_rx.borrow() {
                timeout(Duration::from_secs(1), shutdown_rx.changed())
                    .await
                    .expect("superseded connection was not shut down")
                    .unwrap();
                assert!(*shutdown_rx.borrow());
            }
        }
    }

    #[tokio::test]
    async fn pairing_attempt_cancellation_is_per_device() {
        let attempts = Arc::new(Mutex::new(HashMap::new()));
        let first_id = test_device_id("attempt-first");
        let second_id = test_device_id("attempt-second");
        attempts.lock().await.insert(first_id.clone(), 7);
        attempts.lock().await.insert(second_id.clone(), 13);
        remove_pairing_attempt(&attempts, &first_id).await;
        let guard = attempts.lock().await;
        assert!(!guard.contains_key(&first_id));
        assert_eq!(guard.get(&second_id).copied(), Some(13));
    }

    #[test]
    fn unpaired_resync_packet_is_pair_false_without_timestamp() {
        let pkt = pair_false_packet();
        assert!(matches!(pkt.packet_type, PacketType::Pair));
        let pair = serde_json::from_value::<Pair>(pkt.body).unwrap();
        assert!(!pair.pair);
        assert!(pair.timestamp.is_none());
    }

    #[test]
    fn only_protocol_packets_can_be_sent_before_pairing() {
        use crate::protocol::PacketType as PT;
        let feature_packets = [
            PT::Battery,
            PT::BatteryRequest,
            PT::Clipboard,
            PT::ClipboardConnect,
            PT::ConnectivityReport,
            PT::ConnectivityReportRequest,
            PT::Digitizer,
            PT::DigitizerSession,
            PT::ContactsRequestAllUidsTimestamps,
            PT::ContactsRequestVcardsByUid,
            PT::ContactsResponseUidsTimestamps,
            PT::ContactsResponseVcards,
            PT::FindMyPhoneRequest,
            PT::Lock,
            PT::LockRequest,
            PT::MousePadEcho,
            PT::MousePadKeyboardState,
            PT::MousePadRequest,
            PT::Mpris,
            PT::MprisRequest,
            PT::Notification,
            PT::NotificationAction,
            PT::NotificationReply,
            PT::NotificationRequest,
            PT::Ping,
            PT::Presenter,
            PT::RunCommand,
            PT::RunCommandRequest,
            PT::Sftp,
            PT::SftpRequest,
            PT::ShareRequest,
            PT::ShareRequestUpdate,
            PT::SmsAttachmentFile,
            PT::SmsMessages,
            PT::SmsRequest,
            PT::SmsRequestAttachment,
            PT::SmsRequestConversation,
            PT::SmsRequestConversations,
            PT::SystemVolume,
            PT::SystemVolumeRequest,
            PT::Telephony,
            PT::TelephonyRequestMute,
            PT::Unknown("kdeconnect.future.packet".to_string()),
        ];
        for pt in feature_packets {
            assert!(
                !packet_allowed_for_pair_state(&pt, Some(PairState::NotPaired)),
                "{pt:?} should not be sent before pairing"
            );
            assert!(
                packet_allowed_for_pair_state(&pt, Some(PairState::Paired)),
                "{pt:?} should be sent when paired"
            );
        }
        assert!(packet_allowed_for_pair_state(
            &PT::Pair,
            Some(PairState::NotPaired)
        ));
        assert!(packet_allowed_for_pair_state(
            &PT::Identity,
            Some(PairState::NotPaired)
        ));
    }

    #[tokio::test]
    async fn unpaired_resync_is_throttled_per_device() {
        use std::time::Instant;
        let limiter = UnpairedResyncLimiter::default();
        let first_id = test_device_id("resync-first");
        let second_id = test_device_id("resync-second");
        let now = Instant::now();
        assert!(limiter.should_send_at(&first_id, now).await);
        assert!(!limiter.should_send_at(&first_id, now).await);
        assert!(limiter.should_send_at(&second_id, now).await);
        assert!(
            limiter
                .should_send_at(&first_id, now + UNPAIRED_RESYNC_INTERVAL)
                .await
        );
        limiter.clear(&first_id).await;
        assert!(limiter.should_send_at(&first_id, now).await);
    }
}
