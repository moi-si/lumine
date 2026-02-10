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
	"strings"

	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	"golang.org/x/net/proxy"
)

type Config struct {
	TransmitFileLimit int               `json:"transmit_file_limit"`
	Socks5Addr        string            `json:"socks5_address"`
	HttpAddr          string            `json:"http_address"`
	DNSAddr           string            `json:"dns_addr"`
	UDPSize           uint16            `json:"udp_minsize"`
	DoHProxy          string            `json:"socks5_for_doh"`
	MaxJump           int               `json:"max_jump"`
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
	maxJump       int
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
		dnsExchange = dohExchange
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
		dnsExchange = do53Exchange
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

	if conf.MaxJump <= 0 {
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
			return "", "", fmt.Errorf("load fake ttl rules: %w", err)
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

func getIPPolicy(ip string) *Policy {
	if strings.Contains(ip, ":") {
		policy, _ := ipv6Matcher.Find(ip)
		return policy
	}
	return ipMatcher.Find(ip)
}
