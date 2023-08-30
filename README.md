# pcapan
A pcap capture analysis helper

Usage:
```
$ git clone https://github.com/synacktiv/pcapan
$ cd pcapan
$ cargo run -- --pcap /tmp/capture.pcap --google -w whitelist.yaml
    Finished dev [unoptimized + debuginfo] target(s) in 0.04s
     Running `target/debug/pcapan --pcap /tmp/log.tcpdump --google -w whitelist.yaml`
loading google networks reference
loading google cloud reference
23.63.240.185: ["SNI/p16-sign.tiktokcdn-us.com"] sz=33303
188.166.203.108: ["DNS/www.canardpc.com", "SNI/www.canardpc.com"] sz=10691
199.103.24.8: ?? {443} sz=60 pkt=84639
```

