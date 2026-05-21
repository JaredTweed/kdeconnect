use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, Debug, Default)] #[serde(rename_all = "camelCase")]
pub struct Sftp { pub ip: Option<String>, pub port: Option<u16>, pub user: Option<String>, pub password: Option<String>, pub path: Option<String>, #[serde(default)] pub multi_paths: Vec<String>, #[serde(default)] pub path_names: Vec<String>, pub error_message: Option<String> }
impl crate::plugin_interface::Plugin for Sftp { fn id(&self) -> &'static str { "kdeconnect.sftp" } }
impl Sftp { pub async fn received_packet(self, _device: &crate::device::Device) {} }
