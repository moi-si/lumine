package lumine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
	"github.com/miekg/dns"
	"github.com/moi-si/addrtrie"
	log "github.com/moi-si/mylog"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

const Version = "v0.8.1"

type Config struct {
	LogLevel          string             `json:"log_level"`
	TransmitFileLimit int                `json:"transmit_file_limit"`
	Socks5Addr        string             `json:"socks5_address"`
	HttpAddr          string             `json:"http_address"`
	DNSAddr           string             `json:"dns_addr"`
	UDPSize           uint16             `json:"udp_minsize"`
	DoHProxy          string             `json:"socks5_for_doh"`
	FakeTTLRules      string             `json:"fake_ttl_rules"`
	DNSSingleflight   bool               `json:"dns_singleflight"`
	DNSCacheTTL       int                `json:"dns_cache_ttl"`
	DNSCacheCapacity  int                `json:"dns_cache_cap"`
	TTLSingleflight   bool               `json:"ttl_singleflight"`
	TTLCacheTTL       int                `json:"ttl_cache_ttl"`
	TTLCacheCapacity  int                `json:"ttl_cache_cap"`
	IPPools           map[string]*IPPool `json:"ip_pools"`
	Hosts             map[string]string  `json:"hosts"`
	DefaultPolicy     Policy             `json:"default_policy"`
	DomainPolicies    map[string]Policy  `json:"domain_policies"`
	IpPolicies        map[string]Policy  `json:"ip_policies"`
}

var (
	logLevel      = log.INFO
	defaultPolicy Policy
	IPPools       map[string]*IPPool
	sem           chan struct{}
	dnsAddr       string
	hostsMatcher  *addrtrie.DomainMatcher[string]
	domainMatcher *addrtrie.DomainMatcher[*Policy]
	ipMatcher     *addrtrie.IPv4Trie[*Policy]
	ipv6Matcher   *addrtrie.IPv6Trie[*Policy]
)

func LoadConfig(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	var conf Config
	if err = json.NewDecoder(file).Decode(&conf); err != nil {
		return "", "", err
	}
	file.Close()

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

	if len(conf.IPPools) != 0 {
		IPPools = conf.IPPools
		for tag, pool := range IPPools {
			logger := log.New(os.Stdout, "[P-"+tag+"]", log.LstdFlags, logLevel)
			if err := pool.Init(logger); err != nil {
				return "", "", wrap("init ip pool "+tag, err)
			}
		}
	}

	if conf.DNSSingleflight {
		dnsSingleflight = new(singleflight.Group)
	}
	if conf.TTLSingleflight {
		ttlSingleflight = new(singleflight.Group)
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
			return "", "", wrap("init dns cache", err)
		}
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
			return "", "", wrap("init ttl cache", err)
		}
		ttlCacheTTL = time.Duration(conf.TTLCacheTTL) * time.Second
	}

	if conf.FakeTTLRules != "" {
		err = loadTTLRules(conf.FakeTTLRules)
		if err != nil {
			return "", "", wrap("load fake ttl rules", err)
		}
		if runtime.GOOS == "windows" && conf.TransmitFileLimit > 0 {
			sem = make(chan struct{}, conf.TransmitFileLimit)
		}
	}

	defaultPolicy = conf.DefaultPolicy

	hostsMatcher = addrtrie.NewDomainMatcher[string]()
	for patterns, host := range conf.Hosts {
		for elem := range strings.SplitSeq(patterns, ";") {
			for _, pattern := range expandPattern(elem) {
				hostsMatcher.Add(pattern, host)
			}
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

	ipMatcher = addrtrie.NewIPv4Trie[*Policy]()
	ipv6Matcher = addrtrie.NewIPv6Trie[*Policy]()
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
			dialContext, err = genDoHDialFunc()
			if err != nil {
				return "", "", err
			}
		} else {
			dialer, err := proxy.SOCKS5("tcp", conf.DoHProxy, nil, proxy.Direct)
			if err != nil {
				return "", "", wrap("create socks5 dialer", err)
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
		dnsClient = new(dns.Client)
		if conf.UDPSize > 0 {
			dnsClient.UDPSize = conf.UDPSize
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
	var sniPos, sniLen int
	var hasKeyShare bool
	_, sniPos, sniLen, hasKeyShare, _, err = parseClientHello(b)
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
	case ModeTTLD:
		raddr := c.RemoteAddr().String()
		ipv6 := raddr[0] == '['
		ttl, err := getFakeTTL(nil, dohConnPolicy, raddr, ipv6)
		if err != nil {
			return 0, wrap("get fake TTL", err)
		}
		if err = desyncSend(
			c.Conn, ipv6, b,
			sniPos, sniLen, ttl, dohConnPolicy.FakeSleep,
		); err != nil {
			return 0, wrap("ttl desync", err)
		}
	case ModeTLSRF:
		if err = sendRecords(c.Conn, b, sniPos, sniLen,
			dohConnPolicy.NumRecords, dohConnPolicy.NumSegments,
			dohConnPolicy.OOB == BoolTrue, dohConnPolicy.OOBEx == BoolTrue,
			dohConnPolicy.ModMinorVer == BoolTrue,
			dohConnPolicy.SendInterval); err != nil {
			return 0, wrap("tls fragment", err)
		}
	}
	n = len(b)
	return
}

func hashStringXXHASH(s string) uint32 {
	return uint32(xxhash.Sum64String(s))
}
