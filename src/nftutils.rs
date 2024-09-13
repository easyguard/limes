use ipnet::IpNet;
use nftables::{batch::Batch, expr, helper, schema, stmt, types};

/// Get a statement to match the given IP address.
/// Field should be either "saddr" or "daddr" for matching source or destination.
// pub fn get_ip_match(ip: &IpAddr, field: &str, op: stmt::Operator) -> stmt::Statement {
// 	stmt::Statement::Match(stmt::Match {
// 		left: ip_to_payload(ip, field),
// 		right: expr::Expression::String(ip.to_string()),
// 		op,
// 	})
// }

/// Convert a single IP into a Payload field.
/// Basically, pasts in "ip" or "ip6" in protocol field based on whether this is a v4 or v6 address.
// pub fn ip_to_payload(addr: &IpAddr, field: &str) -> expr::Expression {
// 	let proto = match addr {
// 		IpAddr::V4(_) => "ip".to_string(),
// 		IpAddr::V6(_) => "ip6".to_string(),
// 	};

// 	expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
// 		expr::PayloadField {
// 			protocol: proto,
// 			field: field.to_string(),
// 		},
// 	)))
// }

/// Get a statement to match the given subnet.
/// Field should be either "saddr" or "daddr" for matching source or destination.
pub fn get_subnet_match(net: &IpNet, field: &str, op: stmt::Operator) -> stmt::Statement {
	stmt::Statement::Match(stmt::Match {
		left: subnet_to_payload(net, field),
		right: expr::Expression::Named(expr::NamedExpression::Prefix(expr::Prefix {
			addr: Box::new(expr::Expression::String(net.addr().to_string())),
			len: net.prefix_len() as u32,
		})),
		op,
	})
}

/// Convert a subnet into a Payload field.
/// Basically, pastes in "ip" or "ip6" in protocol field based on whether this
/// is a v4 or v6 subnet.
pub fn subnet_to_payload(net: &IpNet, field: &str) -> expr::Expression {
	let proto = match net {
		IpNet::V4(_) => "ip".to_string(),
		IpNet::V6(_) => "ip6".to_string(),
	};

	expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
		expr::PayloadField {
			protocol: proto,
			field: field.to_string(),
		},
	)))
}
