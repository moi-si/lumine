package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	"golang.org/x/net/proxy"
)

type Mode uint8

const (
	ModeUnknown Mode = iota
	ModeRaw
	ModeDirect
	ModeTLSRF
	ModeTTLD
	ModeBlock
	ModeTLSAlert
)

func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "raw":
		*m = ModeRaw
	case "direct":
		*m = ModeDirect
	case "tls-rf":
		*m = ModeTLSRF
	case "ttl-d":
		*m = ModeTTLD
	case "block":
		*m = ModeBlock
	case "tls-alert":
		*m = ModeTLSAlert
	default:
		return fmt.Errorf("invalid mode: %s", s)
	}
	return nil
}

func (m Mode) String() string {
	switch m {
	case ModeRaw:
		return "raw"
	case ModeDirect:
		return "direct"
	case ModeTLSRF:
		return "tls-rf"
	case ModeTTLD:
		return "ttl-d"
	case ModeBlock:
		return "block"
	case ModeTLSAlert:
		return "tls-alert"
	}
	return "unknown"
}

const (
	defaultTimeout = 30 * time.Second
)

type Policy struct {
	ReplyFirst     BoolWithDefault
	ConnectTimeout time.Duration
	Host           *string
	MapTo          *string
	Port           int16
	DNSRetry       BoolWithDefault
	IPv6First      BoolWithDefault
	HttpStatus     int
	TLS13Only      BoolWithDefault
	Mode           Mode
	NumRecords     int
	NumSegments    int
	OOB            BoolWithDefault
	SendInterval   time.Duration
	FakeTTL        int
	FakeSleep      time.Duration
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var tmp struct {
		ReplyFirst     BoolWithDefault `json:"reply_first"`
		ConnectTimeout *string         `json:"connect_timeout"`
		Host           *string         `json:"host"`
		MapTo          *string         `json:"map_to"`
		Port           *int            `json:"port"`
		DNSRetry       BoolWithDefault `json:"dns_retry"`
		IPv6First      BoolWithDefault `json:"ipv6_first"`
		HttpStatus     *int            `json:"http_status"`
		TLS13Only      BoolWithDefault `json:"tls13_only"`
		Mode           Mode            `json:"mode"`
		NumRecords     *int            `json:"num_records"`
		NumSegments    *int            `json:"num_segs"`
		OOB            BoolWithDefault `json:"oob"`
		SendInterval   *string         `json:"send_Interval"`
		FakeTTL        *int            `json:"fake_ttl"`
		FakeSleep      *string         `json:"fake_sleep"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	p.ReplyFirst = tmp.ReplyFirst
	p.DNSRetry = tmp.DNSRetry
	p.IPv6First = tmp.IPv6First
	p.TLS13Only = tmp.TLS13Only
	p.Mode = tmp.Mode
	p.OOB = tmp.OOB

	if tmp.Host != nil && *tmp.Host == "" {
		return errors.New("host cannot be a empty string")
	} else {
		p.Host = tmp.Host
	}

	if tmp.MapTo != nil && *tmp.MapTo == "" {
		return errors.New("map_to cannot be a empty string")
	} else {
		p.MapTo = tmp.MapTo
	}

	if tmp.Port == nil {
		p.Port = -1
	} else if *tmp.Port < 0 || *tmp.Port > 65535 {
		return fmt.Errorf("invalid port: %d", *tmp.Port)
	} else {
		p.Port = int16(*tmp.Port)
	}

	if tmp.HttpStatus == nil {
		p.HttpStatus = -1
	} else if *tmp.HttpStatus < 0 {
		return fmt.Errorf("invalid http_status: %d", *tmp.HttpStatus)
	} else {
		p.HttpStatus = *tmp.HttpStatus
	}

	if tmp.NumRecords == nil {
		p.NumRecords = 0
	} else if *tmp.NumRecords <= 0 {
		return fmt.Errorf("invalid num_records: %d", *tmp.NumRecords)
	} else {
		p.NumRecords = *tmp.NumRecords
	}

	if tmp.NumSegments == nil {
		p.NumSegments = 0
	} else if *tmp.NumSegments == 0 || *tmp.NumSegments < -1 {
		return fmt.Errorf("invalid num_segs: %d", *tmp.NumSegments)
	} else {
		p.NumSegments = *tmp.NumSegments
	}

	if tmp.FakeTTL == nil {
		p.FakeTTL = -1
	} else if *tmp.FakeTTL < 0 {
		return fmt.Errorf("invalid fake_ttl: %d", *tmp.FakeTTL)
	} else {
		p.FakeTTL = *tmp.FakeTTL
	}

	var err error
	if tmp.ConnectTimeout == nil {
		p.ConnectTimeout = defaultTimeout
	} else {
		p.ConnectTimeout, err = time.ParseDuration(*tmp.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("parse connect_timeout %s: %w", *tmp.ConnectTimeout, err)
		}
		if p.ConnectTimeout <= 0 {
			return errors.New("connect_timeout <= 0")
		}
	}

	if tmp.SendInterval == nil {
		p.SendInterval = -1
	} else {
		p.SendInterval, err = time.ParseDuration(*tmp.SendInterval)
		if err != nil {
			return fmt.Errorf("parse send_interval %s: %w", *tmp.SendInterval, err)
		}
		if p.ConnectTimeout < 0 {
			return errors.New("send_interval < 0")
		}
	}

	if tmp.FakeSleep != nil {
		p.FakeSleep, err = time.ParseDuration(*tmp.FakeSleep)
		if err != nil {
			return fmt.Errorf("parse fake_sleep %s: %w", *tmp.ConnectTimeout, err)
		}
		if p.ConnectTimeout < 0 {
			return errors.New("fake_sleep < minimum fake sleep")
		}
	}

	return nil
}

func (p *Policy) String() string {
	fields := make([]string, 0, 11)
	if p.ConnectTimeout != 0 {
		fields = append(fields, "timeout="+p.ConnectTimeout.String())
	}
	var addr string
	if p.Host != nil && *p.Host != "" {
		addr += *p.Host
	}
	if p.Port != -1 && p.Port != 0 {
		addr += fmt.Sprintf(":%d", p.Port)
	}
	if addr != "" {
		fields = append(fields, addr)
	}
	if p.IPv6First == BoolTrue {
		fields = append(fields, "ipv6_first")
	}
	if p.DNSRetry == BoolTrue {
		fields = append(fields, "resolve_retry")
	}
	if p.HttpStatus > 0 {
		fields = append(fields, "http_status="+strconv.Itoa(p.HttpStatus))
	}
	if p.TLS13Only == BoolTrue {
		fields = append(fields, "tls13_only")
	}
	if p.Mode != ModeUnknown {
		fields = append(fields, p.Mode.String())
		switch p.Mode {
		case ModeTLSRF:
			fields = append(fields, fmt.Sprintf("%d records", p.NumRecords))
			if p.NumSegments != -1 && p.NumSegments != 1 {
				fields = append(fields, fmt.Sprintf("%d segments", p.NumSegments))
			}
			if p.NumSegments != 1 && p.SendInterval > 0 {
				fields = append(fields, "send_interval="+p.SendInterval.String())
			}
			if p.OOB == BoolTrue {
				fields = append(fields, "oob")
			}
		case ModeTTLD:
			if p.FakeTTL == 0 || p.FakeTTL == -1 {
				fields = append(fields, "auto_fake_ttl")
			} else {
				fields = append(fields, fmt.Sprintf("fake_ttl=%d", p.FakeTTL))
			}
			fields = append(fields, "fake_sleep="+p.FakeSleep.String())
		}
	}
	return strings.Join(fields, " | ")
}

func mergePolicies(policies ...Policy) *Policy {
	var merged Policy
	for _, p := range policies {
		if p.ReplyFirst != BoolUnset {
			merged.ReplyFirst = p.ReplyFirst
		}
		if p.Host != nil {
			merged.Host = p.Host
		}
		if p.MapTo != nil {
			merged.MapTo = p.MapTo
		}
		if p.DNSRetry != BoolUnset {
			merged.DNSRetry = p.DNSRetry
		}
		if p.Port != 0 {
			merged.Port = p.Port
		}
		if p.HttpStatus != -1 {
			merged.HttpStatus = p.HttpStatus
		}
		if p.TLS13Only != BoolUnset {
			merged.TLS13Only = p.TLS13Only
		}
		if p.Mode != ModeUnknown {
			merged.Mode = p.Mode
		}
		if p.NumRecords != 0 {
			merged.NumRecords = p.NumRecords
		}
		if p.NumSegments != 0 {
			merged.NumSegments = p.NumSegments
		}
		if p.OOB != BoolUnset {
			merged.OOB = p.OOB
		}
		if p.SendInterval != -1 {
			merged.SendInterval = p.SendInterval
		}
		if p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if p.FakeTTL != -1 {
			merged.FakeTTL = p.FakeTTL
		}
	}
	return &merged
}

type Config struct {
	TransmitFileLimit int               `json:"transmit_file_limit"`
	Socks5Addr        string            `json:"socks5_address"`
	HttpAddr          string            `json:"http_address"`
	DNSAddr           string            `json:"dns_addr"`
	UDPSize           uint16            `json:"udp_minsize"`
	DoHProxy          string            `json:"socks5_for_doh"`
	MaxJump           uint8             `json:"max_jump"`
	FakeTTLRules      string            `json:"fake_ttl_rules"`
	DNSCacheTTL       int               `json:"dns_cache_ttl"`
	TTLCacheTTL       int               `json:"ttl_cache_ttl"`
	DefaultPolicy     Policy            `json:"default_policy"`
	DomainPolicies    map[string]Policy `json:"domain_policies"`
	IpPolicies        map[string]Policy `json:"ip_policies"`
}

var (
	defaultPolicy Policy
	sem           chan struct{}
	dnsAddr       string
	maxJump       uint8
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
	b := []byte(conf)

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

func loadConfig(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var conf Config
	if err = decoder.Decode(&conf); err != nil {
		return "", "", err
	}

	defaultPolicy = conf.DefaultPolicy

	dnsAddr = conf.DNSAddr
	if strings.HasPrefix(dnsAddr, "https://") {
		dnsQuery = dohQuery
		if conf.DoHProxy == "" {
			httpCli = new(http.Client)
		} else {
			dialer, err := proxy.SOCKS5("tcp", conf.DoHProxy, nil, proxy.Direct)
			if err != nil {
				return "", "", fmt.Errorf("create socks5 dialer: %s", err)
			}
			dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(network, address)
			}
			transport := &http.Transport{DialContext: dialContext}
			httpCli = &http.Client{Transport: transport}
		}
	} else {
		dnsQuery = do53Query
		if conf.UDPSize == 0 {
			dnsClient = new(dns.Client)
		} else {
			dnsClient = &dns.Client{UDPSize: conf.UDPSize}
		}
	}

	if conf.DNSCacheTTL < -1 {
		conf.DNSCacheTTL = 0
	}
	if conf.DNSCacheTTL != 0 {
		dnsCacheEnabled = true
		dnsCacheTTL = conf.DNSCacheTTL
	}

	if conf.MaxJump == 0 {
		maxJump = 20
	} else {
		maxJump = conf.MaxJump
	}

	if conf.TTLCacheTTL < -1 {
		conf.TTLCacheTTL = 0
	}
	if conf.TTLCacheTTL != 0 {
		ttlCacheEnabled = true
		ttlCacheTTL = conf.TTLCacheTTL
	}

	if conf.FakeTTLRules != "" {
		err = loadFakeTTLRules(conf.FakeTTLRules)
		if err != nil {
			return "", "", fmt.Errorf("load fake ttl rules: %s", err)
		}
		if runtime.GOOS == "windows" && conf.TransmitFileLimit > 0 {
			sem = make(chan struct{}, conf.TransmitFileLimit)
		}
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

	return conf.Socks5Addr, conf.HttpAddr, nil
}

func matchIP(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	}
	return ipMatcher.Find(ip)
}
