use ipnetwork::Ipv4Network;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    path::PathBuf,
    str::FromStr,
};
use structopt::StructOpt;
use tls_parser::{ClientHello, SNIType};
use x509_parser::prelude::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "pcapan", about = "Analyze pcap files")]
struct Opt {
    /// pcap file
    #[structopt(short, long)]
    pcap: PathBuf,

    /// white list file
    #[structopt(short, long, default_value = "whitelist.yaml")]
    whitelist: PathBuf,

    /// cutoff conversation size
    #[structopt(short, long, default_value = "0")]
    cutoff: usize,

    /// load google ranges on the internet
    #[structopt(long)]
    google: bool,
}

#[derive(Debug, serde::Deserialize)]
struct Config {
    dns: HashMap<String, String>,
    allow: HashMap<String, String>,
    su: HashMap<String, String>,
    oksuffixes: HashSet<String>,
    okhosts: HashSet<String>,
}

fn network_parse(k: String) -> Ipv4Network {
    let (n, p) = match k.split_once('/') {
        Some((i, p)) => (Ipv4Addr::from_str(i).unwrap(), p.parse().unwrap()),
        None => (Ipv4Addr::from_str(&k).unwrap(), 32),
    };
    Ipv4Network::new(n, p).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
enum DataSource {
    SNI,
    DNS,
    HttpHost,
}

struct CollectedInfo {
    ports: HashSet<u16>,
    hosts: HashSet<(DataSource, String)>,
    size: usize,
    first_packet: usize,
}

impl CollectedInfo {
    fn new(first_packet: usize) -> Self {
        Self {
            ports: Default::default(),
            hosts: Default::default(),
            size: 0,
            first_packet,
        }
    }
}

#[derive(Default)]
struct ParsedData {
    inner: HashMap<Ipv4Addr, CollectedInfo>,
}

impl ParsedData {
    fn hostname(
        &mut self,
        packet_id: usize,
        dsrc: DataSource,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        content: String,
    ) {
        self.insert_hostname(packet_id, dsrc, src, content.clone());
        self.insert_hostname(packet_id, dsrc, dst, content);
    }

    fn ports(&mut self, packet_id: usize, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) {
        self.inner
            .entry(src)
            .or_insert_with(|| CollectedInfo::new(packet_id))
            .ports
            .insert(sport);
        self.inner
            .entry(dst)
            .or_insert_with(|| CollectedInfo::new(packet_id))
            .ports
            .insert(dport);
    }

    fn datasize(&mut self, packet_id: usize, src: Ipv4Addr, dst: Ipv4Addr, size: usize) {
        self.inner
            .entry(src)
            .or_insert_with(|| CollectedInfo::new(packet_id))
            .size += size;
        self.inner
            .entry(dst)
            .or_insert_with(|| CollectedInfo::new(packet_id))
            .size += size;
    }

    fn insert_hostname(
        &mut self,
        packet_id: usize,
        dsrc: DataSource,
        src: Ipv4Addr,
        content: String,
    ) {
        if !src.is_private() {
            self.inner
                .entry(src)
                .or_insert_with(|| CollectedInfo::new(packet_id))
                .hosts
                .insert((dsrc, content));
        }
    }
}

#[derive(Deserialize)]
struct GoogleNetwork {
    #[serde(alias = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    service: Option<String>,
}
#[derive(Deserialize)]
struct GoogleNetworks {
    prefixes: Vec<GoogleNetwork>,
}

fn main() {
    let opt = Opt::from_args();
    let f = std::fs::File::open(opt.whitelist).unwrap();
    let config: Config = serde_yaml::from_reader(f).unwrap();

    let mut whitelist = config
        .allow
        .into_keys()
        .map(network_parse)
        .collect::<Vec<_>>();
    let dns = config
        .dns
        .into_keys()
        .map(network_parse)
        .collect::<Vec<_>>();
    let mut suspicious = config
        .su
        .into_iter()
        .map(|(k, v)| (network_parse(k), v))
        .collect::<Vec<_>>();

    if opt.google {
        eprintln!("loading google networks reference");
        let goog: GoogleNetworks =
            reqwest::blocking::get("https://www.gstatic.com/ipranges/goog.json")
                .unwrap()
                .json()
                .unwrap();
        eprintln!("loading google cloud reference");
        let cloud: GoogleNetworks =
            reqwest::blocking::get("https://www.gstatic.com/ipranges/cloud.json")
                .unwrap()
                .json()
                .unwrap();
        for n in goog.prefixes {
            if let Some(p) = n.ipv4_prefix {
                whitelist.push(network_parse(p))
            }
        }
        for (nb, n) in cloud.prefixes.into_iter().enumerate() {
            if let Some(p) = n.ipv4_prefix {
                suspicious.push((
                    network_parse(p),
                    n.service.unwrap_or_else(|| nb.to_string()),
                ))
            }
        }
    }

    let mut capture = pcap::Capture::from_file(opt.pcap).unwrap();

    let mut ips = ParsedData::default();
    let mut packet_id: usize = 0;

    while let Ok(packet) = capture.next_packet() {
        packet_id += 1;
        let d = pdu::EthernetPdu::new(packet.data).unwrap();
        if let Ok(pdu::Ethernet::Ipv4(e)) = d.inner() {
            let src = Ipv4Addr::from(e.source_address());
            let dst = Ipv4Addr::from(e.destination_address());
            let content = e.buffer();
            ips.datasize(packet_id, src, dst, content.len());
            match e.protocol() {
                6 => {
                    let header_len = e.as_bytes().len();
                    let tcp = &content[header_len..];
                    if tcp.len() < 20 {
                        eprintln!("{:?}", tcp);
                    }
                    let data_offset = (tcp[12] as usize >> 4) * 4;
                    let payload = &tcp[data_offset..];
                    if let Ok((_, record)) = tls_parser::parse_tls_plaintext(payload) {
                        for m in record.msg {
                            if let tls_parser::TlsMessage::Handshake(hs) = m {
                                match hs {
                                    tls_parser::TlsMessageHandshake::ClientHello(ch) => {
                                        if let Some(ext) = ch.ext() {
                                            if let Ok((_, extensions)) =
                                                tls_parser::parse_tls_extensions(ext)
                                            {
                                                for e in extensions {
                                                    if let tls_parser::TlsExtension::SNI(snis) = e {
                                                        for (tp, content) in snis {
                                                            match tp {
                                                                SNIType::HostName => ips.hostname(
                                                                    packet_id,
                                                                    DataSource::SNI,
                                                                    src,
                                                                    dst,
                                                                    String::from_utf8_lossy(
                                                                        content,
                                                                    )
                                                                    .into_owned(),
                                                                ),
                                                                _ => ips.hostname(
                                                                    packet_id,
                                                                    DataSource::SNI,
                                                                    src,
                                                                    dst,
                                                                    format!(
                                                                        "{}/{}",
                                                                        tp,
                                                                        String::from_utf8_lossy(
                                                                            content
                                                                        )
                                                                    ),
                                                                ),
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    tls_parser::TlsMessageHandshake::Certificate(tlscerts) => {
                                        for c in tlscerts.cert_chain {
                                            match X509Certificate::from_der(c.data) {
                                                Ok((_, _)) => {
                                                    println!("TODO: parse server certificate at packet {}", packet_id)
                                                }
                                                Err(rr) => eprintln!(
                                                    "error when parsing certificate at packet {}: {}",
                                                    packet_id, rr
                                                ),
                                            }
                                        }
                                    }
                                    tls_parser::TlsMessageHandshake::CertificateRequest(_) => {
                                        println!(
                                            "TODO: parse certificate request at packet {}",
                                            packet_id
                                        )
                                    }
                                    _ => (),
                                }
                            }
                        }
                    }
                    let mut headers = [httparse::EMPTY_HEADER; 64];
                    let mut request = httparse::Request::new(&mut headers);
                    if let Ok(httparse::Status::Complete(_)) = request.parse(payload) {
                        for h in request.headers.iter() {
                            if h.name.to_ascii_lowercase() == "host" {
                                ips.hostname(
                                    packet_id,
                                    DataSource::HttpHost,
                                    src,
                                    dst,
                                    String::from_utf8_lossy(h.value).into_owned(),
                                );
                            }
                        }
                    }
                    let sport = tcp[1] as u16 + (tcp[0] as u16 * 256);
                    let dport = tcp[3] as u16 + (tcp[2] as u16 * 256);
                    ips.ports(packet_id, src, dst, sport, dport);
                }
                17 => {
                    let header_len = e.as_bytes().len();
                    let udp = &content[header_len..];
                    if udp.len() <= 8 {
                        eprintln!("short udp packet {}?", packet_id);
                        continue;
                    }
                    let sport = udp[1] as u16 + (udp[0] as u16 * 256);
                    let dport = udp[3] as u16 + (udp[2] as u16 * 256);
                    let payload = &udp[8..];
                    ips.ports(packet_id, src, dst, sport, dport);
                    if dns.iter().any(|n| n.contains(src)) {
                        // packet from dns server
                        match dns_parser::Packet::parse(payload) {
                            Ok(m) => {
                                let questions = m
                                    .questions
                                    .into_iter()
                                    .filter_map(|q| {
                                        if q.qtype == dns_parser::QueryType::A {
                                            Some(q.qname.to_string())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<HashSet<_>>();
                                for answer in m.answers {
                                    if let dns_parser::RData::A(rcd) = answer.data {
                                        let aname = answer.name.to_string();
                                        if questions.contains(&aname) {
                                            ips.hostname(
                                                packet_id,
                                                DataSource::DNS,
                                                dst,
                                                rcd.0,
                                                aname,
                                            );
                                        }
                                    }
                                }
                            }
                            Err(rr) => {
                                eprintln!("packet {}, can't parse as DNS: {}", packet_id, rr)
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }

    let mut ips = ips.inner.into_iter().collect::<Vec<_>>();
    ips.sort_by_key(|p| p.0);

    let ok_host = |d: &str| {
        config.okhosts.contains(d) || config.oksuffixes.iter().any(|suff| d.ends_with(suff))
    };

    for (ip, info) in ips {
        if ip.is_private() || ip.is_broadcast() || ip.is_multicast() {
            continue;
        }
        if info.size < opt.cutoff {
            continue;
        }
        if dns.iter().any(|n| n.contains(ip)) {
            continue;
        }
        if whitelist.iter().all(|n| !n.contains(ip)) {
            if !info.hosts.is_empty() {
                if info.hosts.iter().any(|d| !ok_host(&d.1)) {
                    println!(
                        "{}: {:?} sz={}",
                        ip,
                        info.hosts
                            .iter()
                            .map(|(src, nm)| format!("{:?}/{}", src, nm))
                            .collect::<Vec<_>>(),
                        info.size
                    );
                }
            } else if let Some(x) = suspicious.iter().find(|(n, _)| n.contains(ip)) {
                println!(
                    "{}: {} {:?} sz={} pkt={}",
                    ip, x.1, info.ports, info.size, info.first_packet
                );
            } else {
                println!(
                    "{}: ?? {:?} sz={} pkt={}",
                    ip, info.ports, info.size, info.first_packet
                );
            }
        }
    }
}
