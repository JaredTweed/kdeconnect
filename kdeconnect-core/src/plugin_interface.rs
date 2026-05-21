use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    sync::{RwLock, mpsc},
};
use tracing::{debug, error, info, warn};

use crate::{
    GLOBAL_CONFIG,
    device::Device,
    event::{ConnectionEvent, CoreEvent},
    filetransfer::{TransferAdapter, send_progress},
    protocol::{PacketPayloadTransferInfo, PacketType, ProtocolPacket},
    transport::prepare_listener_for_payload,
};

pub trait Plugin: Sync + Send {
    fn id(&self) -> &'static str;
}

/// Maps a PacketType to the logical plugin ID used in settings.
/// Returns None for core packets (Identity, Pair) that are never gated.
fn packet_plugin_id(pt: &PacketType) -> Option<&'static str> {
    match pt {
        PacketType::Battery | PacketType::BatteryRequest => Some("battery"),
        PacketType::Clipboard | PacketType::ClipboardConnect => Some("clipboard"),
        PacketType::ConnectivityReport | PacketType::ConnectivityReportRequest => {
            Some("connectivity_report")
        }
        PacketType::Digitizer | PacketType::DigitizerSession => Some("digitizer"),
        PacketType::ContactsResponseUidsTimestamps
        | PacketType::ContactsResponseVcards
        | PacketType::ContactsRequestAllUidsTimestamps
        | PacketType::ContactsRequestVcardsByUid => Some("contacts"),
        PacketType::FindMyPhoneRequest => Some("findmyphone"),
        PacketType::Mpris | PacketType::MprisRequest => Some("mpris"),
        PacketType::Notification
        | PacketType::NotificationAction
        | PacketType::NotificationReply
        | PacketType::NotificationRequest => Some("notification"),
        PacketType::Ping => Some("ping"),
        PacketType::RunCommand | PacketType::RunCommandRequest => Some("runcommand"),
        PacketType::ShareRequest | PacketType::ShareRequestUpdate => Some("share"),
        PacketType::Sftp | PacketType::SftpRequest => Some("sftp"),
        PacketType::SmsMessages
        | PacketType::SmsRequest
        | PacketType::SmsRequestConversations
        | PacketType::SmsRequestConversation
        | PacketType::SmsAttachmentFile
        | PacketType::SmsRequestAttachment => Some("sms"),
        PacketType::SystemVolume | PacketType::SystemVolumeRequest => Some("systemvolume"),
        PacketType::MousePadEcho
        | PacketType::MousePadKeyboardState
        | PacketType::MousePadRequest => Some("mousepad"),
        PacketType::Presenter => Some("presenter"),
        PacketType::Telephony | PacketType::TelephonyRequestMute => Some("telephony"),
        PacketType::Lock | PacketType::LockRequest => Some("lock"),
        // Core / unmanaged packets are never gated
        PacketType::Identity | PacketType::Pair | PacketType::Unknown(_) => None,
    }
}

/// A type-erased packet handler stored in the registry.
type HandlerFn = dyn Fn(
        Device,
        serde_json::Value,
        mpsc::UnboundedSender<CoreEvent>,
        mpsc::UnboundedSender<ConnectionEvent>,
        mpsc::UnboundedSender<ConnectionEvent>,
        Option<PacketPayloadTransferInfo>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>
    + Send
    + Sync;

#[derive(Clone)]
pub struct PluginRegistry {
    plugins: Arc<RwLock<Vec<Arc<dyn Plugin>>>>,
    /// PacketType → handler function (registered at startup).
    handlers: Arc<RwLock<HashMap<PacketType, Arc<HandlerFn>>>>,
    /// device_id.0 → set of disabled plugin IDs
    disabled: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(Vec::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            disabled: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, plugin: Arc<dyn Plugin>) {
        let mut plugins = self.plugins.write().await;
        info!("Registering plugin: {}", plugin.id());
        plugins.push(plugin);
    }

    /// Register a handler for a specific PacketType.
    pub async fn register_handler(&self, packet_type: PacketType, handler: Arc<HandlerFn>) {
        self.handlers.write().await.insert(packet_type, handler);
    }

    /// Replace the disabled set for a device (called on connect and on toggle).
    pub async fn set_device_disabled(&self, device_id: &str, disabled: HashSet<String>) {
        self.disabled
            .write()
            .await
            .insert(device_id.to_string(), disabled);
    }

    /// Returns true if the plugin is currently enabled for this device.
    pub async fn is_plugin_enabled(&self, device_id: &str, plugin_id: &str) -> bool {
        let guard = self.disabled.read().await;
        guard
            .get(device_id)
            .map(|set| !set.contains(plugin_id))
            .unwrap_or(true)
    }

    pub async fn dispatch(
        &self,
        device: Device,
        packet: ProtocolPacket,
        core_tx: mpsc::UnboundedSender<CoreEvent>,
        tx: mpsc::UnboundedSender<ConnectionEvent>,
        mpris_tx: mpsc::UnboundedSender<ConnectionEvent>,
    ) {
        // Gate on plugin enabled state before doing any work.
        if let Some(plugin_id) = packet_plugin_id(&packet.packet_type)
            && !self.is_plugin_enabled(&device.device_id.0, plugin_id).await
        {
            debug!(
                "[plugin_registry] packet {:?} skipped — plugin '{}' disabled for {}",
                packet.packet_type, plugin_id, device.device_id
            );
            return;
        }

        info!("[dispatch] packet type: {:?}", packet.packet_type);

        if let Some(handler) = self.handlers.read().await.get(&packet.packet_type).cloned() {
            handler(
                device,
                packet.body.clone(),
                core_tx,
                tx,
                mpris_tx,
                packet.payload_transfer_info,
            )
            .await;
        } else {
            debug!(
                "No handler registered for packet type: {:?}",
                packet.packet_type
            );
        }
    }

    /// Send a packet that carries a binary payload (file / album art).
    pub async fn send_payload(
        &self,
        packet: ProtocolPacket,
        device_writer: &mpsc::UnboundedSender<ProtocolPacket>,
        mut payload: TransferAdapter<impl AsyncRead + Sync + Send + Unpin + 'static>,
        payload_size: u64,
    ) {
        info!("preparing payload transfer");

        let free_listener = match prepare_listener_for_payload().await {
            Ok(l) => l,
            Err(e) => {
                warn!("cannot find free port: {}", e);
                return;
            }
        };

        let addr = match free_listener.local_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!("cannot get local addr for payload listener: {}", e);
                return;
            }
        };

        debug!("payload listener bound on {}", addr);
        let payload_transfer_info = Some(PacketPayloadTransferInfo { port: addr.port() });
        let body = packet.body.clone();

        match packet.packet_type {
            PacketType::Mpris => {
                if let Ok(mpris) = serde_json::from_value::<crate::plugins::mpris::Mpris>(body) {
                    let _ = mpris
                        .send_art(device_writer, payload_size, payload_transfer_info)
                        .await;
                }
            }
            PacketType::ShareRequest => {
                if let Ok(share_request) =
                    serde_json::from_value::<crate::plugins::share::ShareRequest>(body)
                {
                    let _ = share_request
                        .send_file(device_writer, payload_size, payload_transfer_info)
                        .await;
                }
            }
            _ => {
                error!(
                    "[payload] unsupported payload type: {:?}; payload dropped",
                    packet.packet_type
                );
                return;
            }
        }

        let server_config = GLOBAL_CONFIG.get().unwrap().key_store.server_config.clone();
        tokio::spawn(async move {
            let (incoming, peer_addr) = match free_listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    warn!("[payload] accepting connection failed: {}", e);
                    return;
                }
            };
            debug!("[payload] incoming connection from {}", peer_addr);

            let mut stream = match tokio_rustls::TlsAcceptor::from(server_config)
                .accept(incoming)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!("[payload] TLS handshake failed: {}", e);
                    return;
                }
            };

            debug!("[payload] TLS accepted, copying payload");
            if let Err(e) = tokio::io::copy(&mut payload, &mut stream).await {
                warn!("[payload] copy failed: {}", e);
                return;
            }
            if let Err(e) = stream.flush().await {
                warn!("[payload] flush failed: {}", e);
                return;
            }
            let _ = stream.shutdown().await;
            send_progress(100, payload.notify_tx.clone());
            info!("[payload] successfully sent payload to {}", peer_addr);
        });
    }

    pub async fn send(
        &self,
        device: Device,
        packet: ProtocolPacket,
        core_tx: mpsc::UnboundedSender<CoreEvent>,
    ) {
        let body = packet.body.clone();
        let core_event = core_tx.clone();

        match packet.packet_type {
            PacketType::Ping => {
                if let Ok(ping) = serde_json::from_value::<crate::plugins::ping::Ping>(body) {
                    ping.send_packet(&device, core_event).await;
                }
            }
            PacketType::MprisRequest => {
                if let Ok(mpris_request) =
                    serde_json::from_value::<crate::plugins::mpris::MprisRequest>(body)
                {
                    mpris_request.send_packet(&device, core_event).await;
                }
            }
            _ => {
                warn!(
                    "No plugin found to handle packet type: {:?}",
                    packet.packet_type
                );
            }
        }
    }

    pub async fn list_plugins(&self) -> Vec<String> {
        let plugins = self.plugins.read().await;
        plugins.iter().map(|p| p.id().to_string()).collect()
    }
}
