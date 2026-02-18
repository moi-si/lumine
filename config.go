package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-freelru"
	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	log "github.com/moi-si/mylog"
	"golang.org/x/net/proxy"
)

type Config struct {
	LogLevel          string             `json:"log_level"`
	TransmitFileLimit int                `json:"transmit_file_limit"`
	Socks5Addr        string             `json:"socks5_address"`
	HttpAddr          string             `json:"http_address"`
	DNSAddr           string             `json:"dns_addr"`
	UDPSize           uint16             `json:"udp_minsize"`
	DoHProxy          string             `json:"socks5_for_doh"`
	FakeTTLRules      string             `json:"fake_ttl_rules"`
	DNSCacheTTL       int                `json:"dns_cache_ttl"`
	DNSCacheCapacity  int                `json:"dns_cache_cap"`
	TTLCacheTTL       int                `json:"ttl_cache_ttl"`
	TTLCacheCapacity  int                `json:"ttl_cache_cap"`
	IPPools           map[string]*IPPool `json:"ip_pools"`
	DefaultPolicy     Policy             `json:"default_policy"`
	DomainPolicies    map[string]Policy  `json:"domain_policies"`
	IpPolicies        map[string]Policy  `json:"ip_policies"`
}

var (
	logLevel      = log.INFO
	defaultPolicy Policy
	ipPools       map[string]*IPPool
	sem           chan struct{}
	dnsAddr       string
	calcTTL       func(int) (int, error)
	domainMatcher *addrtrie.DomainMatcher[*Policy]
	ipMatcher     *addrtrie.BitTrie[*Policy]
	ipv6Matcher   *addrtrie.BitTrie6[*Policy]
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

	if conf.LogLevel != "" {
		switch strings.ToUpper(conf.LogLevel) {
		case "DEBUG":
			logLevel = log.DEBUG
		case "INFO":
			logLevel = log.INFO
		case "ERROR":
			logLevel = log.ERROR
		default:
			return "", "", errors.New("unknown log level: " + conf.LogLevel)
		}
	}

	defaultPolicy = conf.DefaultPolicy
	if len(conf.IPPools) != 0 {
		ipPools = conf.IPPools
		for tag, pool := range ipPools {
			logger := log.New(os.Stdout, "<"+tag+">", log.LstdFlags, logLevel)
			logger.Info("Testing...")
			if err := pool.Init(logger); err != nil {
				return "", "", fmt.Errorf("init ip pool %s: %w", tag, err)
			}
		}
	}

	if conf.DNSCacheTTL < 0 {
		return "", "", errors.New("invalid dns_cache_ttl: " + strconv.Itoa(conf.DNSCacheTTL))
	}
	if conf.DNSCacheTTL != 0 {
		if conf.DNSCacheCapacity < 1 {
			return "", "", errors.New("invalid dns_cache_cap: " + strconv.Itoa(conf.DNSCacheCapacity))
		}
		dnsCache, err = freelru.NewSharded[string, string](uint32(conf.DNSCacheCapacity), hashStringXXHASH)
		if err != nil {
			return "", "", fmt.Errorf("init dns cache: %w", err)
		}
		dnsCacheEnabled = true
		dnsCacheTTL = time.Duration(conf.DNSCacheTTL) * time.Second
	}

	if conf.TTLCacheTTL < 0 {
		return "", "", errors.New("invalid ttl cache ttl: " + strconv.Itoa(conf.TTLCacheTTL))
	}
	if conf.TTLCacheTTL != 0 {
		if conf.TTLCacheCapacity < 1 {
			return "", "", errors.New("invalid ttl_cache_cap: " + strconv.Itoa(conf.TTLCacheCapacity))
		}
		ttlCache, err = freelru.NewSharded[string, int](uint32(conf.TTLCacheCapacity), hashStringXXHASH)
		if err != nil {
			return "", "", fmt.Errorf("init ttl cache: %w", err)
		}
		ttlCacheEnabled = true
		ttlCacheTTL = time.Duration(conf.TTLCacheTTL) * time.Second
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

	domainMatcher = addrtrie.NewDomainMatcher[*Policy]()
	for patterns, policy := range conf.DomainPolicies {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				domainMatcher.Add(pattern, &policy)
			}
		}
	}

	ipMatcher = addrtrie.NewBitTrie[*Policy]()
	ipv6Matcher = addrtrie.NewBitTrie6[*Policy]()
	for patterns, policy := range conf.IpPolicies {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, ipOrNet := range expandPattern(elem) {
				if isIPv6(ipOrNet) {
					ipv6Matcher.Insert(ipOrNet, &policy)
				} else {
					ipMatcher.Insert(ipOrNet, &policy)
				}
			}
		}
	}

	dnsAddr = conf.DNSAddr
	if strings.HasPrefix(dnsAddr, "https://") {
		var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if conf.DoHProxy == "" {
			dialContext, err = genDialContext()
			if err != nil {
				return "", "", err
			}
		} else {
			dialer, err := proxy.SOCKS5("tcp", conf.DoHProxy, nil, proxy.Direct)
			if err != nil {
				return "", "", fmt.Errorf("create socks5 dialer: %w", err)
			}
			dialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = dialContext
		httpCli = &http.Client{Transport: transport}
		dnsExchange = dohExchange
	} else {
		dnsExchange = do53Exchange
		if conf.UDPSize == 0 {
			dnsClient = new(dns.Client)
		} else {
			dnsClient = &dns.Client{UDPSize: conf.UDPSize}
		}
	}

	return conf.Socks5Addr, conf.HttpAddr, nil
}

func getIPPolicy(ip string) (*Policy, bool) {
	if isIPv6(ip) {
		return ipv6Matcher.Find(ip)
	}
	return ipMatcher.Find(ip)
}

var dohConnPolicy *Policy

type interceptConn struct {
	net.Conn
	handled bool
}

func (c *interceptConn) Write(b []byte) (n int, err error) {
	if c.handled {
		return c.Conn.Write(b)
	}
	c.handled = true
	switch dohConnPolicy.Mode {
	case ModeBlock, ModeTLSAlert:
		return 0, errors.New("blocked by policy")
	case ModeTTLD:
		return 0, errors.ErrUnsupported
	}
	var sniPos, sniLen int
	var hasKeyShare bool
	_, sniPos, sniLen, hasKeyShare, err = parseClientHello(b)
	if err != nil {
		return
	}
	if dohConnPolicy.TLS13Only == BoolTrue && !hasKeyShare {
		return 0, errors.New("not a TLS 1.3 ClientHello")
	}
	if sniPos == -1 {
		return c.Conn.Write(b)
	}
	switch dohConnPolicy.Mode {
	case ModeDirect, ModeRaw:
		return c.Conn.Write(b)
	case ModeTLSRF:
		err = sendRecords(c.Conn, b, sniPos, sniLen,
			dohConnPolicy.NumRecords, dohConnPolicy.NumSegments,
			dohConnPolicy.OOB == BoolTrue, dohConnPolicy.ModMinorVer == BoolTrue,
			dohConnPolicy.SendInterval)
	}
	if err == nil {
		n = len(b)
	}
	return
}

func genDialContext() (func(ctx context.Context, network, address string) (net.Conn, error), error) {
	parsedURL, err := url.Parse(dnsAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}
	host := parsedURL.Hostname()
	dohConnPolicy = new(Policy)
	if net.ParseIP(host) != nil {
		var ipPolicy *Policy
		host, ipPolicy, err = ipRedirect(nil, host)
		if ipPolicy == nil {
			dohConnPolicy = &defaultPolicy
		} else {
			p := mergePolicies(ipPolicy, &defaultPolicy)
			dohConnPolicy = &p
		}
		if err != nil {
			return nil, fmt.Errorf("ip redirect: %w", err)
		}
	} else {
		var disableRedirect bool
		domainPolicy, found := domainMatcher.Find(host)
		if found {
			p := mergePolicies(domainPolicy, &defaultPolicy)
			dohConnPolicy = &p
		} else {
			dohConnPolicy = &defaultPolicy
		}
		if dohConnPolicy.Host != nil && *dohConnPolicy.Host != "" {
			disableRedirect = (*dohConnPolicy.Host)[0] == '^'
			if disableRedirect {
				host = (*dohConnPolicy.Host)[1:]
			} else {
				host = *dohConnPolicy.Host
			}
			if strings.HasPrefix(host, tagPrefix) {
				if host, err = getFromIPPool(host[1:]); err != nil {
					return nil, err
				}
			}
			if !disableRedirect {
				var ipPolicy *Policy
				host, ipPolicy, err = ipRedirect(nil, host)
				if err != nil {
					return nil, fmt.Errorf("ip redirect: %w", err)
				}
				if ipPolicy != nil {
					var p Policy
					if found {
						p = mergePolicies(domainPolicy, ipPolicy, &defaultPolicy)
					} else {
						p = mergePolicies(ipPolicy, &defaultPolicy)
					}
					dohConnPolicy = &p
				}
			}
		}
	}
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	if dohConnPolicy.Port != unsetInt {
		port = strconv.FormatInt(int64(dohConnPolicy.Port), 10)
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: dohConnPolicy.ConnectTimeout}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			return &interceptConn{Conn: conn}, nil
		}
		return nil, err
	}, nil
}
