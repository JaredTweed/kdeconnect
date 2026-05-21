use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, Debug, Default)] #[serde(rename_all = "camelCase")]
pub struct DigitizerSession { pub action: Option<String>, pub width: Option<i32>, pub height: Option<i32> }
impl crate::plugin_interface::Plugin for DigitizerSession { fn id(&self) -> &'static str { "digitizer-session" } }
impl DigitizerSession { pub async fn received_packet(&self) {} }
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DigitizerEvent { pub active: Option<bool>, pub touching: Option<bool>, pub tool: Option<String>, pub x: Option<i32>, pub y: Option<i32>, pub pressure: Option<f64> }
impl crate::plugin_interface::Plugin for DigitizerEvent { fn id(&self) -> &'static str { "digitizer" } }
impl DigitizerEvent { pub async fn received_packet(&self) {} }
