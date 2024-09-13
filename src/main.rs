mod config;
mod nftutils;

use std::str::FromStr;

use clap::{crate_name, Parser, Subcommand};
use config::Ruleset;
use ipnet::IpNet;
use nftables::{batch::Batch, expr, helper, schema, stmt, types};

const FILTER_TABLE_FAMILY: types::NfFamily = types::NfFamily::INet;
const FILTER_TABLE_NAME: &str = "filter";
const FILTER_INPUT_CHAIN_NAME: &str = "input";
const FILTER_FORWARD_CHAIN_NAME: &str = "forward";
const NAT_TABLE_FAMILY: types::NfFamily = types::NfFamily::INet;
const NAT_TABLE_NAME: &str = "nat";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
	#[arg(short, long)]
	verbose: bool,

	/// The ruleset file to apply
	#[arg(short, long, default_value_t = String::from("/etc/config/firewall.json"))]
	ruleset: String,

	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	/// Apply the ruleset to the system firewall
	Apply {},
}

fn main() {
	let args: Args = Args::parse();

	match &args.command {
		Commands::Apply {} => apply_cmd(&args),
	}
}

fn apply_cmd(args: &Args) {
	let config = config::read_ruleset(&args.ruleset)
		.expect("Failed to read ruleset! Is it formatted correctly?");
	let ruleset = generate_ruleset(&config, args);
	helper::apply_ruleset(&ruleset, None, None).unwrap();
	// let nftables = serde_json::to_string(&ruleset).expect("failed to serialize Nftables struct");
	// println!("{}", nftables);

	println!("[{}] Done!", crate_name!())
}

fn generate_ruleset(config: &Ruleset, args: &Args) -> schema::Nftables {
	let mut batch = Batch::new();
	// flush command
	batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Ruleset(None)));

	generate_filter_table(&mut batch, config, args);
	generate_nat_table(&mut batch, config, args);

	batch.to_nftables()
}

// =================
// INET FILTER TABLE
// =================

fn generate_filter_table(batch: &mut Batch, config: &Ruleset, args: &Args) {
	batch.add(schema::NfListObject::Table(schema::Table::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
	)));

	generate_filter_input_chain(batch, config, args);
	generate_filter_forward_chain(batch, config, args);
}

fn generate_filter_input_chain(batch: &mut Batch, config: &Ruleset, args: &Args) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		Some(types::NfChainType::Filter),
		Some(types::NfHook::Input),
		Some(0),
		None,
		Some(types::NfChainPolicy::Drop),
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
					dir: None,
				})),
				right: expr::Expression::List(vec![
					expr::Expression::String("established".to_string()),
					expr::Expression::String("related".to_string()),
				]),
				op: stmt::Operator::IN,
			}),
			stmt::Statement::Accept(None),
		],
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
					dir: None,
				})),
				right: expr::Expression::String("invalid".to_string()),
				op: stmt::Operator::EQ,
			}),
			stmt::Statement::Drop(None),
		],
	)));

	// Drop obviously spoofed loopback traffic
	// iifname "lo" ip daddr != 127.0.0.0/8 drop
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
					key: expr::MetaKey::Iifname,
				})),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ,
			}),
			nftutils::get_subnet_match(
				&IpNet::from_str("127.0.0.0/8").unwrap(),
				"daddr",
				stmt::Operator::NEQ,
			),
			stmt::Statement::Drop(None),
		],
	)));

	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_INPUT_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
					key: expr::MetaKey::Iifname,
				})),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ,
			}),
			stmt::Statement::Accept(None),
		],
	)));

	// TEMP: Allow all traffic
	// batch.add(schema::NfListObject::Rule(schema::Rule::new(
	// 	FILTER_TABLE_FAMILY,
	// 	FILTER_TABLE_NAME.to_string(),
	// 	FILTER_INPUT_CHAIN_NAME.to_string(),
	// 	vec![
	// 		stmt::Statement::Accept(None)
	// 	]
	// )));

	for zone in &config.zones {
		if zone.input.ports.is_none() {
			continue;
		}
		if args.verbose { println!("[filter input] Generating chain for {} zone", zone.name); }
		batch.add(schema::NfListObject::Chain(schema::Chain::new(
			FILTER_TABLE_FAMILY,
			FILTER_TABLE_NAME.to_string(),
			format!("input_{}", zone.name),
			None,
			None,
			None,
			None,
			None,
		)));
		let ifs: Vec<expr::SetItem> = zone
			.items
			.interfaces
			.iter()
			.map(|interface| expr::SetItem::Element(expr::Expression::String(interface.clone())))
			.collect();
		if args.verbose { println!("[filter input] Interfaces: {:?}", ifs); }
		batch.add(schema::NfListObject::Rule(schema::Rule::new(
			FILTER_TABLE_FAMILY,
			FILTER_TABLE_NAME.to_string(),
			FILTER_INPUT_CHAIN_NAME.to_string(),
			vec![
				stmt::Statement::Match(stmt::Match {
					left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
						key: expr::MetaKey::Iifname,
					})),
					right: expr::Expression::Named(expr::NamedExpression::Set(ifs)),
					op: stmt::Operator::IN,
				}),
				stmt::Statement::Jump(stmt::JumpTarget {
					target: format!("input_{}", zone.name),
				}),
			],
		)));
		let port_rules = zone.input.ports.as_ref().unwrap();
		for rule in port_rules {
			add_rule(
				rule,
				batch,
				FILTER_TABLE_FAMILY,
				FILTER_TABLE_NAME.to_string(),
				format!("input_{}", zone.name),
				args
			);
		}
	}
}

fn generate_filter_forward_chain(batch: &mut Batch, config: &Ruleset, args: &Args) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		Some(types::NfChainType::Filter),
		Some(types::NfHook::Forward),
		Some(0),
		None,
		Some(types::NfChainPolicy::Drop),
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
					dir: None,
				})),
				right: expr::Expression::List(vec![
					expr::Expression::String("established".to_string()),
					expr::Expression::String("related".to_string()),
				]),
				op: stmt::Operator::IN,
			}),
			stmt::Statement::Accept(None),
		],
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
					dir: None,
				})),
				right: expr::Expression::String("invalid".to_string()),
				op: stmt::Operator::EQ,
			}),
			stmt::Statement::Drop(None),
		],
	)));

	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		FILTER_TABLE_FAMILY,
		FILTER_TABLE_NAME.to_string(),
		FILTER_FORWARD_CHAIN_NAME.to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
					key: expr::MetaKey::Iifname,
				})),
				right: expr::Expression::String("lo".to_string()),
				op: stmt::Operator::EQ,
			}),
			stmt::Statement::Accept(None),
		],
	)));

	// TEMP: Allow all traffic
	// batch.add(schema::NfListObject::Rule(schema::Rule::new(
	// 	FILTER_TABLE_FAMILY,
	// 	FILTER_TABLE_NAME.to_string(),
	// 	FILTER_FORWARD_CHAIN_NAME.to_string(),
	// 	vec![
	// 		stmt::Statement::Match(stmt::Match {
	// 			left: expr::Expression::Named(expr::NamedExpression::Meta(
	// 				expr::Meta {
	// 					key: expr::MetaKey::Iifname
	// 				}
	// 			)),
	// 			right: expr::Expression::String("eth1".to_string()),
	// 			op: stmt::Operator::EQ
	// 		}),
	// 		stmt::Statement::Accept(None)
	// 	]
	// )));

	for zone in &config.zones {
		if zone.forward.is_empty() {
			continue;
		}
		if args.verbose { println!("[filter forward] Generating chains for {} zone", zone.name); }
		for subzone in &zone.forward {
			// subzone.dest is just the name of the destination zone, we need to get the actual interface of the zone
			let dest_zone = config
				.zones
				.iter()
				.find(|z| z.name == subzone.dest)
				.unwrap();
			let dest_if = &dest_zone.items.interfaces[0];
			batch.add(schema::NfListObject::Chain(schema::Chain::new(
				FILTER_TABLE_FAMILY,
				FILTER_TABLE_NAME.to_string(),
				format!("forward_{}_{}", zone.name, subzone.dest),
				None,
				None,
				None,
				None,
				None,
			)));
			let ifs: Vec<expr::SetItem> = zone
				.items
				.interfaces
				.iter()
				.map(|interface| {
					expr::SetItem::Element(expr::Expression::String(interface.clone()))
				})
				.collect();
			if args.verbose { println!("[filter forward] Interfaces: {:?}", ifs); }
			batch.add(schema::NfListObject::Rule(schema::Rule::new(
				FILTER_TABLE_FAMILY,
				FILTER_TABLE_NAME.to_string(),
				FILTER_FORWARD_CHAIN_NAME.to_string(),
				vec![
					stmt::Statement::Match(stmt::Match {
						left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
							key: expr::MetaKey::Iifname,
						})),
						right: expr::Expression::Named(expr::NamedExpression::Set(ifs)),
						op: stmt::Operator::IN,
					}),
					stmt::Statement::Match(stmt::Match {
						left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
							key: expr::MetaKey::Oifname,
						})),
						right: expr::Expression::String(dest_if.to_string()),
						op: stmt::Operator::EQ,
					}),
					stmt::Statement::Jump(stmt::JumpTarget {
						target: format!("forward_{}_{}", zone.name, subzone.dest),
					}),
				],
			)));
			let port_rules = &subzone.ports;
			for rule in port_rules {
				add_rule(
					rule,
					batch,
					FILTER_TABLE_FAMILY,
					FILTER_TABLE_NAME.to_string(),
					format!("forward_{}_{}", zone.name, subzone.dest),
					args
				);
			}
		}
	}
}

fn add_rule(
	rule: &config::PortRule,
	batch: &mut Batch,
	table_family: types::NfFamily,
	table_name: String,
	chain: String,
	args: &Args
) {
	let mut expr: Vec<stmt::Statement> = Vec::new();
	if rule.protocol == "icmp" {
		panic!("ICMP not supported yet!");
	} else {
		if rule.limit.is_some() {
			panic!("Limit not supported yet!");
		}
		if args.verbose { println!("[add_rule] Adding rule: {}/{}", rule.port.unwrap(), rule.protocol); }
		expr.push(stmt::Statement::Match(stmt::Match {
			left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
				key: expr::MetaKey::L4proto,
			})),
			right: expr::Expression::String(rule.protocol.clone()),
			op: stmt::Operator::EQ,
		}));
		expr.push(stmt::Statement::Match(stmt::Match {
			left: expr::Expression::Named(expr::NamedExpression::Payload(
				expr::Payload::PayloadField(expr::PayloadField {
					protocol: "th".to_string(),
					field: "dport".to_string(),
				}),
			)),
			right: expr::Expression::Number(rule.port.unwrap() as u32),
			op: stmt::Operator::EQ,
		}));
		expr.push(stmt::Statement::Accept(None));
	}
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		table_family,
		table_name,
		chain,
		expr,
	)))
}

// =========
// NAT TABLE
// =========

fn generate_nat_table(batch: &mut Batch, config: &Ruleset, args: &Args) {
	batch.add(schema::NfListObject::Table(schema::Table::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
	)));

	generate_nat_prerouting_chain(batch, config, args);
	generate_nat_postrouting_chain(batch, config, args);
}

fn generate_nat_prerouting_chain(batch: &mut Batch, _config: &Ruleset, _args: &Args) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"prerouting".to_string(),
		Some(types::NfChainType::NAT),
		Some(types::NfHook::Prerouting),
		Some(0),
		None,
		None,
	)));
}

fn generate_nat_postrouting_chain(batch: &mut Batch, _config: &Ruleset, _args: &Args) {
	batch.add(schema::NfListObject::Chain(schema::Chain::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"postrouting".to_string(),
		Some(types::NfChainType::NAT),
		Some(types::NfHook::Postrouting),
		Some(0),
		None,
		Some(types::NfChainPolicy::Accept),
	)));
	batch.add(schema::NfListObject::Rule(schema::Rule::new(
		NAT_TABLE_FAMILY,
		NAT_TABLE_NAME.to_string(),
		"postrouting".to_string(),
		vec![
			stmt::Statement::Match(stmt::Match {
				left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
					key: expr::MetaKey::Oifname,
				})),
				right: expr::Expression::String("eth0".to_string()),
				op: stmt::Operator::EQ,
			}),
			stmt::Statement::Masquerade(None),
		],
	)));
}
