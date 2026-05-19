use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, mpsc, watch};

use crate::{
    device::{DeviceId, PairState},
    protocol::{PacketType, Pair, ProtocolPacket},
};

/// Maximum allowed difference between device clocks for pairing (30 minutes in seconds).
pub(crate) const ALLOWED_TIMESTAMP_DIFF_SECS: u64 = 1800;

/// Auto-reject incoming/outgoing pairing requests after this duration (30 seconds).
pub(crate) const PAIRING_TIMEOUT_SECS: u64 = 30;
pub(crate) const UNPAIRED_RESYNC_INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const UNPAIRED_RESYNC_DROP_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub(crate) struct ConnectionHandle {
    pub(crate) write_tx: mpsc::UnboundedSender<ProtocolPacket>,
    pub(crate) shutdown_tx: watch::Sender<bool>,
}

pub(crate) async fn install_connection(
    writer_map: &Arc<Mutex<HashMap<DeviceId, ConnectionHandle>>>,
    conn_id_map: &Arc<Mutex<HashMap<DeviceId, u64>>>,
    device_id: DeviceId,
    conn_id: u64,
    handle: ConnectionHandle,
) {
    let previous_handle = {
        let mut writers = writer_map.lock().await;
        let mut conn_ids = conn_id_map.lock().await;
        conn_ids.insert(device_id.clone(), conn_id);
        writers.insert(device_id, handle)
    };
    if let Some(previous_handle) = previous_handle {
        let _ = previous_handle.shutdown_tx.send(true);
    }
}

pub(crate) async fn remove_connection(
    writer_map: &Arc<Mutex<HashMap<DeviceId, ConnectionHandle>>>,
    conn_id_map: &Arc<Mutex<HashMap<DeviceId, u64>>>,
    device_id: &DeviceId,
) -> bool {
    let removed = {
        let mut writers = writer_map.lock().await;
        let mut conn_ids = conn_id_map.lock().await;
        conn_ids.remove(device_id);
        writers.remove(device_id)
    };
    if let Some(handle) = removed {
        let _ = handle.shutdown_tx.send(true);
        true
    } else {
        false
    }
}

pub(crate) async fn is_current_connection(
    conn_id_map: &Arc<Mutex<HashMap<DeviceId, u64>>>,
    device_id: &DeviceId,
    conn_id: u64,
) -> bool {
    let guard = conn_id_map.lock().await;
    guard
        .get(device_id)
        .map(|&current| current == conn_id)
        .unwrap_or(false)
}

pub(crate) async fn remove_connection_if_current(
    writer_map: &Arc<Mutex<HashMap<DeviceId, ConnectionHandle>>>,
    conn_id_map: &Arc<Mutex<HashMap<DeviceId, u64>>>,
    device_id: &DeviceId,
    conn_id: u64,
) -> bool {
    let removed = {
        let mut writers = writer_map.lock().await;
        let mut conn_ids = conn_id_map.lock().await;
        if conn_ids.get(device_id).copied() != Some(conn_id) {
            return false;
        }
        conn_ids.remove(device_id);
        writers.remove(device_id)
    };
    if let Some(handle) = removed {
        let _ = handle.shutdown_tx.send(true);
        true
    } else {
        false
    }
}

pub(crate) async fn remove_pairing_attempt(
    pairing_attempts: &Arc<Mutex<HashMap<DeviceId, u64>>>,
    device_id: &DeviceId,
) {
    pairing_attempts.lock().await.remove(device_id);
}

pub(crate) fn pair_false_packet() -> ProtocolPacket {
    let pair = Pair::reject();
    let value = serde_json::to_value(pair).expect("fail serializing pair");
    ProtocolPacket::new(PacketType::Pair, value)
}

pub(crate) fn packet_allowed_for_pair_state(
    packet_type: &PacketType,
    pair_state: Option<PairState>,
) -> bool {
    matches!(packet_type, PacketType::Pair | PacketType::Identity)
        || pair_state == Some(PairState::Paired)
}

#[derive(Default)]
pub(crate) struct UnpairedResyncLimiter {
    last_sent: Mutex<HashMap<DeviceId, Instant>>,
}

impl UnpairedResyncLimiter {
    pub(crate) async fn should_send(&self, device_id: &DeviceId) -> bool {
        self.should_send_at(device_id, Instant::now()).await
    }

    pub(crate) async fn should_send_at(&self, device_id: &DeviceId, now: Instant) -> bool {
        let mut guard = self.last_sent.lock().await;
        if let Some(last_sent) = guard.get(device_id)
            && now.duration_since(*last_sent) < UNPAIRED_RESYNC_INTERVAL
        {
            return false;
        }
        guard.insert(device_id.clone(), now);
        true
    }

    pub(crate) async fn clear(&self, device_id: &DeviceId) {
        self.last_sent.lock().await.remove(device_id);
    }
}
