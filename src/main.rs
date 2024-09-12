mod nftutils;

use std::str::FromStr;

use ipnet::IpNet;
use nftables::{batch::Batch, expr, helper, schema, stmt, types};

const FILTER_TABLE_FAMILY: types::NfFamily = types::NfFamily::INet;
const FILTER_TABLE_NAME: &str = "filter";
const FILTER_INPUT_CHAIN_NAME: &str = "input";
const FILTER_FORWARD_CHAIN_NAME: &str = "forward";
const NAT_TABLE_FAMILY: types::NfFamily = types::NfFamily::INet;
const NAT_TABLE_NAME: &str = "nat";

fn main() {
	let ruleset = generate_ruleset();
	helper::apply_ruleset(&ruleset, None, None).unwrap();
}

fn generate_ruleset() -> schema::Nftables {
	let mut batch = Batch::new();
	// flush command
	batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Ruleset(None)));

	generate_filter_table(&mut batch);
	generate_nat_table(&mut batch);
	
	batch.to_nftables()
}

// =================
// INET FILTER TABLE
// =================

fn generate_filter_table(batch: &mut Batch) {
	batch.add(schema::NfListObject::Table(schema::Table::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string()
	)));

	generate_filter_input_chain(batch);
	generate_filter_forward_chain(batch);
}

fn generate_filter_input_chain(batch: &mut Batch) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		Some(types::NfChainType::Filter),
		Some(types::NfHook::Input),
		Some(0),
		None,
		Some(types::NfChainPolicy::Drop)
	)));

	// Input chain
	// Allow established and related connections: Allows Internet servers to respond to requests from our Internal network
	// ct state vmap { established : accept, related : accept, invalid : drop} counter
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
					key: "state".to_string(),
					family: None,
					dir: None
				})),
				right: expr::Expression::List(vec![
					expr::Expression::String("established".to_string()),
					expr::Expression::String("related".to_string())
				]),
				op: stmt::Operator::IN
			}),
			stmt::Statement::Accept(None)
		]
	)));
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
					key: "state".to_string(),
					family: None,
					dir: None
				})),
				right: expr::Expression::String("invalid".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Drop(None)
		]
	)));

	// Drop obviously spoofed loopback traffic
	// iifname "lo" ip daddr != 127.0.0.0/8 drop
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(
					expr::Meta {
						key: expr::MetaKey::Iifname
					}
				)),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ
			}),
			nftutils::get_subnet_match(&IpNet::from_str("127.0.0.0/8").unwrap(), "daddr", stmt::Operator::NEQ),
			stmt::Statement::Drop(None)
		]
	)));

	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(
					expr::Meta {
						key: expr::MetaKey::Iifname
					}
				)),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Accept(None)
		]
	)));

	// TEMP: Allow all traffic
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Accept(None)
		]
	)));
}

fn generate_filter_forward_chain(batch: &mut Batch) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		Some(types::NfChainType::Filter),
		Some(types::NfHook::Forward),
		Some(0),
		None,
		Some(types::NfChainPolicy::Drop)
	)));
	// Allow established and related connections: Allows Internet servers to respond to requests from our Internal network
	// ct state vmap { established : accept, related : accept, invalid : drop} counter
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
					key: "state".to_string(),
					family: None,
					dir: None
				})),
				right: expr::Expression::List(vec![
					expr::Expression::String("established".to_string()),
					expr::Expression::String("related".to_string())
				]),
				op: stmt::Operator::IN
			}),
			stmt::Statement::Accept(None)
		]
	)));
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
					key: "state".to_string(),
					family: None,
					dir: None
				})),
				right: expr::Expression::String("invalid".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Drop(None)
		]
	)));

	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(
					expr::Meta {
						key: expr::MetaKey::Iifname
					}
				)),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Accept(None)
		]
	)));

	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(
					expr::Meta {
						key: expr::MetaKey::Iifname
					}
				)),
				right: expr::Expression::String("eth1".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Accept(None)
		]
	)));
}

// =========
// NAT TABLE
// =========

fn generate_nat_table(batch: &mut Batch) {
	batch.add(schema::NfListObject::Table(schema::Table::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string()
	)));

	generate_nat_prerouting_chain(batch);
	generate_nat_postrouting_chain(batch);
}

fn generate_nat_prerouting_chain(batch: &mut Batch) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"prerouting".to_string(),
		Some(types::NfChainType::NAT),
		Some(types::NfHook::Prerouting),
		Some(0),
		None,
		None
	)));
}

fn generate_nat_postrouting_chain(batch: &mut Batch) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"postrouting".to_string(),
		Some(types::NfChainType::NAT),
		Some(types::NfHook::Postrouting),
		Some(0),
		None,
		Some(types::NfChainPolicy::Accept)
	)));
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"postrouting".to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(
					expr::Meta {
						key: expr::MetaKey::Oifname
					}
				)),
				right: expr::Expression::String("eth0".to_string()),
				op: stmt::Operator::EQ
			}),
			stmt::Statement::Masquerade(None)
		]
	)));
}
