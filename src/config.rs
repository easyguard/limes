use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Ruleset {
	pub zones: Vec<Zone>,
	pub forwards: Vec<Forward>,
}

#[derive(Serialize, Deserialize)]
pub struct Zone {
	pub name: String,
	pub input: Chain,
	pub output: Chain,
	pub forward: Vec<ForwardItem>,
	pub items: Items,
}

#[derive(Serialize, Deserialize)]
pub struct Chain {
	pub ports: Option<Vec<PortRule>>,
	pub include: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct ForwardItem {
	pub dest: String,
	pub ports: Vec<PortRule>,
	pub include: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct PortRule {
	pub protocol: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub r#type: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub limit: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub port: Option<u16>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub source_ip: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dest_ip: Option<String>
}

#[derive(Serialize, Deserialize)]
pub struct Items {
	pub interfaces: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Forward {
	pub src: String,
	pub dest: String,
	pub dest_ip: String,
	pub port: u16,
	pub protocol: String,
}

pub fn read_ruleset(file: &str) -> Result<Ruleset, std::io::Error> {
	let ruleset = std::fs::read_to_string(file)?;
	Ok(serde_json::from_str(&ruleset)?)
}

pub fn read_template(file: &str) -> Result<Vec<PortRule>, std::io::Error> {
	let template = std::fs::read_to_string(file)?;
	Ok(serde_json::from_str(&template)?)
}
