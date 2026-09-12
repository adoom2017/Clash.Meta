use anyhow::{Result, bail, ensure};
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub enum Matcher {
    Domain(String),
    Suffix(String),
    Keyword(String),
    Net(ipnet::IpNet),
    Port(u16),
    Network(String),
    All,
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub matcher: Matcher,
    pub target: String,
    pub no_resolve: bool,
}
impl Rule {
    pub fn parse(raw: &str) -> Result<Self> {
        let fields: Vec<_> = raw.split(',').map(str::trim).collect();
        ensure!(fields.len() >= 2, "rule needs type and target");
        if fields[0] == "MATCH" {
            ensure!(fields.len() == 2, "MATCH takes one target");
            return Ok(Self {
                matcher: Matcher::All,
                target: fields[1].into(),
                no_resolve: true,
            });
        }
        ensure!(
            fields.len() == 3
                || (fields.len() == 4
                    && fields[3] == "no-resolve"
                    && matches!(fields[0], "IP-CIDR" | "IP-CIDR6")),
            "invalid rule fields"
        );
        let value = fields[1].to_ascii_lowercase();
        ensure!(!value.is_empty(), "empty rule value");
        let matcher = match fields[0] {
            "DOMAIN" => Matcher::Domain(value.trim_end_matches('.').into()),
            "DOMAIN-SUFFIX" => Matcher::Suffix(value.trim_matches('.').into()),
            "DOMAIN-KEYWORD" => Matcher::Keyword(value),
            "IP-CIDR" | "IP-CIDR6" => {
                let net: ipnet::IpNet = value.parse()?;
                ensure!(
                    net.addr().is_ipv4() == (fields[0] == "IP-CIDR"),
                    "rule IP family mismatch"
                );
                Matcher::Net(net)
            }
            "DST-PORT" => Matcher::Port(value.parse()?),
            "NETWORK" => {
                ensure!(value == "tcp" || value == "udp", "invalid network");
                Matcher::Network(value)
            }
            _ => bail!("unsupported rule type {}", fields[0]),
        };
        Ok(Self {
            matcher,
            target: fields[2].into(),
            no_resolve: fields.len() == 4,
        })
    }
    pub fn matches(&self, host: &str, ip: Option<IpAddr>, port: u16, network: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match &self.matcher {
            Matcher::Domain(d) => host == *d,
            Matcher::Suffix(d) => {
                host == *d
                    || host
                        .strip_suffix(d)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            Matcher::Keyword(k) => host.contains(k),
            Matcher::Net(n) => ip.is_some_and(|ip| n.contains(&ip)),
            Matcher::Port(p) => *p == port,
            Matcher::Network(n) => n == network,
            Matcher::All => true,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suffix_label_boundary() {
        let rule = Rule::parse("DOMAIN-SUFFIX,example.org,DIRECT").unwrap();
        assert!(rule.matches("WWW.Example.org.", None, 443, "tcp"));
        assert!(!rule.matches("notexample.org", None, 443, "tcp"));
    }
}
