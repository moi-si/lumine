# lumine
A lightweight local HTTP/SOCKS5 proxy server that protects TLS connections over TCP.

## Installation

```
go install github.com/moi-si/lumine@latest
```

## Build

```
git clone https://github.com/moi-si/lumine
cd lumine
go build
```

## Configuration
### Top-Level Fields
Field|Description|Example|Special Values
-|-|-|-
`socks5_address`|SOCKS5 bind address|`"127.0.0.1:1080"`|`"none"` disables SOCKS5 proxy
`http_address`|HTTP bind address|`":1225"`|`"none"` disables HTTP proxy
`dns_addr`|DNS over UDP/HTTPS server address for resolution|`"127.0.0.1:8053"`, `"https://1.1.1.1/dns-query"`|-
`udp_minsize`|Minimum UDP packet size for DNS queries|`4096`|`0` uses default DNS client size (may cause error)
`socks5_for_doh`|SOCKS5 proxy server address for DoH|`"127.0.0.1:1080"`|Empty string disables proxy
`max_jump`|Maximum redirect chain length for IP mapping|`30`|`0` defaults to 20
`fake_ttl_rules`|TTL calculation rules for fake packets|`"0-1;3=3;5-1;8-2;13-3;20=18"`|Empty string disables TTL rules
`transmit_file_limit`|Maximum concurrent TransmitFile operations|`2`|`0` or negative means no limit (unrestricted concurrency)
`default_policy`|Default policy applied to all connections|See Policy fields below|-
`domain_policy`|Domain-specific policies|See Policy fields below|-
`ip_policy`|IP/CIDR-specific policies|See Policy fields below|-
### Policy Fields
Field|Description|Example|Special Values
-|-|-|-
`reply_first`|Send SOCKS5 reply SUCCESS before connecting|`true`|-
`host`|Override target host|`"^208.103.161.2"`, `"www.ietf.org"`|Prefix `^` disables IP redirection
`map_to`|Redirect IP to another host/CIDR|`"35.180.16.12"`, `"^www.fbi.org"`|Prefix `^` disables chain jump
`port`|Override target port|`8443`|`0` uses original port
`dns_retry`|Enable dual DNS query (A+AAAA)|`false`|-
`ipv6_first`|Prefer IPv6 over IPv4 resolution|`false`|-
`http_status`|HTTP status code to return instead of forwarding|`301`|`0` means forward normally
`tls13_only`|Restrict to TLS 1.3 only|`true`|-
`mode`|Traffic manipulation mode|`"tls-rf"`|See Mode Values below
`num_records`|Number of TLS records for fragmentation|`10`|`1` disables fragmentation
`num_segs`|Number of segments for TCP fragmentation|`3`|`1` disables segment splitting; when `-1`, send 1 record each time
`oob`|Attach Out-Of-Band (OOB) data to the end of the first TCP segment|`true`|-
`send_delay`|Delay between sending segments (seconds)|`0.3`|`0` or negative means no delay
`fake_ttl`|TTL value for fake packets in `ttl-d` mode|`17`|`0` enables auto TTL detection
`fake_sleep`|Sleep time after sending fake packet (seconds)|`0.2`|-
### Mode  Values
Mode|Description|Used For
-|-|-
`raw`|Raw TCP forwarding after SOCKS5|Minimal overhead
`direct`|Pass-through without manipulation|General traffic
`tls-rf`|TLS record fragmentation|TLS connections
`ttl-d`|TTL-based desynchronization with fake packets|TLS connections
`block`|Block connection entirely|Connection termination
`tls-alert`|Send TLS alert and terminate connection|TLS connection termination

## Local DNS over UDP
See [YkDNS](https://github.com/moi-si/ykdns).

## License

GPL-3.0
