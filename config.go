package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	"golang.org/x/text/encoding/charmap"
)

type Policy struct {
	ReplyFirst *bool   `json:"reply_first"`
	Host       *string `json:"host"`
	MapTo      *string `json:"map_to"`
	Port       *uint16 `json:"port"`
	DNSRetry   *bool   `json:"dns_retry"`
	IPv6First  *bool   `json:"ipv6_first"`
	HttpStatus int     `json:"http_status"`
	TLS13Only  *bool   `json:"tls13_only"`
	Mode       string  `json:"mode"`
	NumRecords int     `json:"num_records"`
	FakeTTL    int     `json:"fake_ttl"`
	FakeSleep  float64 `json:"fake_sleep"`
}

func (p Policy) String() string {
	fields := make([]string, 0, 9)
	var addr string
	if p.Host != nil && *p.Host != "" {
		addr += *p.Host
	}
	if p.Port != nil && *p.Port != 0 {
		addr += fmt.Sprintf(":%d", *p.Port)
	}
	if addr != "" {
		fields = append(fields, addr)
	}
	if p.IPv6First != nil && *p.IPv6First {
		fields = append(fields, "ipv6_first")
	}
	if p.DNSRetry != nil && *p.DNSRetry {
		fields = append(fields, "resolve_retry")
	}
	if p.HttpStatus != 0 {
		fields = append(fields, fmt.Sprintf("http_status=%d", p.HttpStatus))
	}
	if p.TLS13Only != nil && *p.TLS13Only {
		fields = append(fields, "tls13_only")
	}
	fields = append(fields, p.Mode)
	switch p.Mode {
	case "tls-rf":
		fields = append(fields, fmt.Sprintf("%d records", p.NumRecords))
	case "ttl-d":
		if p.FakeTTL == 0 {
			fields = append(fields, "auto_fake_ttl")
		} else {
			fields = append(fields, fmt.Sprintf("fake_ttl=%d", p.FakeTTL))
		}
		fields = append(fields, fmt.Sprintf("fake_sleep=%v", p.FakeSleep))
	}
	return strings.Join(fields, " | ")
}

func mergePolicies(policies ...Policy) *Policy {
	var merged Policy
	for _, p := range policies {
		if p.ReplyFirst != nil {
			merged.ReplyFirst = p.ReplyFirst
		}
		if p.Host != nil {
			merged.Host = p.Host
		}
		if p.MapTo != nil {
			merged.MapTo = p.MapTo
		}
		if p.DNSRetry != nil {
			merged.DNSRetry = p.DNSRetry
		}
		if p.Port != nil {
			merged.Port = p.Port
		}
		if p.HttpStatus != 0 {
			merged.HttpStatus = p.HttpStatus
		}
		if p.TLS13Only != nil {
			merged.TLS13Only = p.TLS13Only
		}
		if p.Mode != "" {
			merged.Mode = p.Mode
		}
		if p.NumRecords != 0 {
			merged.NumRecords = p.NumRecords
		}
		if p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if p.FakeTTL != 0 {
			merged.FakeTTL = p.FakeTTL
		}
	}
	return &merged
}

type Config struct {
	ServerAddr        string            `json:"server_address"`
	DNSAddr           string            `json:"udp_dns_addr"`
	UDPSize           uint16            `json:"udp_minsize"`
	DefaultHttpPolicy int               `json:"default_http_policy"`
	FakePacket        string            `json:"fake_packet"`
	FakeTTLRules      string            `json:"fake_ttl_rules"`
	DefaultPolicy     Policy            `json:"default_policy"`
	DomainPolicies    map[string]Policy `json:"domain_policies"`
	IpPolicies        map[string]Policy `json:"ip_policies"`
}

var (
	defaultPolicy Policy
	fakePacket    []byte
	dnsAddr       string
	calcTTL       func(int) (int, error)
	domainMatcher *addrtrie.DomainMatcher[Policy]
	ipMatcher     *addrtrie.BitTrie[Policy]
	ipv6Matcher   *addrtrie.BitTrie6[Policy]
)

type rule struct {
	threshold int  // a
	typ       byte // '-' or '='
	val       int  // b
}

func parseRules(conf string) ([]rule, error) {
	if len(conf) == 0 {
		return nil, errors.New("empty config")
	}
	if conf[0] != 'q' {
		return nil, nil
	}
	b := []byte(conf[1:])

	var rules []rule
	i := 0
	for i < len(b) {
		start := i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, errors.New("invalid rule: missing left number")
		}
		a := 0
		for _, c := range b[start:i] {
			a = a*10 + int(c-'0')
		}

		if i >= len(b) {
			return nil, errors.New("invalid rule: missing operator")
		}
		op := b[i] // '-' or '='
		if op != '-' && op != '=' {
			return nil, errors.New("invalid operator")
		}
		i++

		start = i
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if start == i {
			return nil, errors.New("invalid rule: missing right number")
		}
		val := 0
		for _, c := range b[start:i] {
			val = val*10 + int(c-'0')
		}

		rules = append(rules, rule{
			threshold: a,
			typ:       op,
			val:       val,
		})

		if i < len(b) && b[i] == ';' {
			i++
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].threshold > rules[j].threshold
	})
	return rules, nil
}

func loadFakeTTLRules(conf string) error {
	rules, err := parseRules(conf)
	if err != nil {
		return err
	}
	if rules == nil {
		calcTTL = func(int) (int, error) {
			val := 0
			for i := range len(conf) {
				c := conf[i]
				if c < '0' || c > '9' {
					return 0, errors.New("invalid integer config")
				}
				val = val*10 + int(c-'0')
			}
			return val, nil
		}
	} else {
		calcTTL = func(ttl int) (int, error) {
			for _, r := range rules {
				if ttl >= r.threshold {
					if r.typ == '-' {
						return ttl - r.val, nil
					}
					// r.typ == '='
					return r.val, nil
				}
			}
			return 0, errors.New("no matching TTL rule")
		}
	}
	return nil
}

func loadConfig(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var conf Config
	if err = decoder.Decode(&conf); err != nil {
		return "", err
	}
	defaultPolicy = conf.DefaultPolicy
	dnsAddr = conf.DNSAddr
	if conf.UDPSize == 0 {
		dnsClient = new(dns.Client)
	} else {
		dnsClient = &dns.Client{UDPSize: conf.UDPSize}
	}
	if conf.FakePacket != "" {
		var encoder = charmap.ISO8859_1.NewEncoder()
		if fakePacket, err = encoder.Bytes([]byte(conf.FakePacket)); err != nil {
			return "", fmt.Errorf("fake packet encoding failed: %v", err)
		}
	}
	if conf.FakeTTLRules != "" {
		loadFakeTTLRules(conf.FakeTTLRules)
	}

	domainMatcher = addrtrie.NewDomainMatcher[Policy]()
	for patterns, policy := range conf.DomainPolicies {
		p := policy
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				domainMatcher.Add(pattern, p)
			}
		}
	}

	ipMatcher = addrtrie.NewBitTrie[Policy]()
	ipv6Matcher = addrtrie.NewBitTrie6[Policy]()
	for patterns, policy := range conf.IpPolicies {
		p := policy
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, ipOrNet := range expandPattern(elem) {
				if strings.Contains(ipOrNet, ":") {
					ipv6Matcher.Insert(ipOrNet, p)
				} else {
					ipMatcher.Insert(ipOrNet, p)
				}
			}
		}
	}

	return conf.ServerAddr, nil
}

func matchIP(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	}
	return ipMatcher.Find(ip)
}
