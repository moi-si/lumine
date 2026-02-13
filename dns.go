package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/elastic/go-freelru"
	"github.com/miekg/dns"
)

type DNSMode uint8

const (
	DNSModeUnknown DNSMode = iota
	DNSModePreferIPv4
	DNSModePreferIPv6
	DNSModeIPv4Only
	DNSModeIPv6Only
	DNSModeDefault = DNSModePreferIPv4
)

func (m DNSMode) String() string {
	switch m {
	case DNSModePreferIPv4:
		return "prefer_ipv4"
	case DNSModePreferIPv6:
		return "prefer_ipv6"
	case DNSModeIPv4Only:
		return "ipv4_only"
	case DNSModeIPv6Only:
		return "ipv6_only"
	}
	return "unknown"
}

func (m *DNSMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "prefer_ipv4":
		*m = DNSModePreferIPv4
	case "prefer_ipv6":
		*m = DNSModePreferIPv6
	case "ipv4_only":
		*m = DNSModeIPv4Only
	case "ipv6_only":
		*m = DNSModeIPv6Only
	default:
		return errors.New("invalid dns_mode: " + s)
	}
	return nil
}

var (
	dnsClient       *dns.Client
	httpCli         *http.Client
	dnsExchange     func(req *dns.Msg) (resp *dns.Msg, err error)
	dnsCacheEnabled bool
	dnsCache        *freelru.ShardedLRU[string, string]
	dnsCacheTTL     time.Duration
)

func do53Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	resp, _, err = dnsClient.Exchange(req, dnsAddr)
	return resp, err
}

func dohExchange(req *dns.Msg) (resp *dns.Msg, err error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns request: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(wire)
	u := dnsAddr + "?dns=" + b64
	httpReq, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build http request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	httpResp, err := httpCli.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http status: %s", httpResp.Status)
	}
	respWire, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read http body: %w", err)
	}
	resp = new(dns.Msg)
	if err = resp.Unpack(respWire); err != nil {
		return nil, fmt.Errorf("unpack dns response: %w", err)
	}
	return
}

func pickFirstARecord(answer []dns.RR) string {
	for _, ans := range answer {
		if record, ok := ans.(*dns.A); ok {
			return record.A.String()
		}
	}
	return ""
}

func pickFirstAAAARecord(answer []dns.RR) string {
	for _, ans := range answer {
		if record, ok := ans.(*dns.AAAA); ok {
			return record.AAAA.String()
		}
	}
	return ""
}

func dnsResolve(domain string, dnsMode DNSMode) (ip string, cached bool, err error) {
	if dnsCacheEnabled {
		if ip, ok := dnsCache.Get(domain); ok {
			return ip, true, nil
		}
	}

	msg := new(dns.Msg)
	switch dnsMode {
	case DNSModePreferIPv4, DNSModeIPv4Only:
		msg.SetQuestion(domain+".", dns.TypeA)
	case DNSModePreferIPv6, DNSModeIPv6Only:
		msg.SetQuestion(domain+".", dns.TypeAAAA)
	}

	resp, err := dnsExchange(msg)
	if err != nil {
		return "", false, fmt.Errorf("dns exchange: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", false, errors.New("bad rcode: " + dns.RcodeToString[resp.Rcode])
	}

	switch dnsMode {
	case DNSModeIPv4Only:
		ip = pickFirstARecord(resp.Answer)
		if ip == "" {
			return "", false, errors.New("A record not found")
		}
	case DNSModeIPv6Only:
		ip = pickFirstAAAARecord(resp.Answer)
		if ip == "" {
			return "", false, errors.New("AAAA record not found")
		}
	case DNSModePreferIPv4:
		ip = pickFirstARecord(resp.Answer)
		if ip == "" {
			msg.SetQuestion(domain+".", dns.TypeAAAA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", false, fmt.Errorf("dns exchange: %w; %w", err, err2)
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", false, fmt.Errorf("bad rcode: %s", dns.RcodeToString[resp.Rcode])
			}
			ip = pickFirstAAAARecord(resp.Answer)
			if ip == "" {
				return "", false, errors.New("record not found")
			}
		}
	case DNSModePreferIPv6:
		ip = pickFirstAAAARecord(resp.Answer)
		if ip == "" {
			msg.SetQuestion(domain+".", dns.TypeA)
			resp, err2 := dnsExchange(msg)
			if err2 != nil {
				return "", false, fmt.Errorf("dns exchange: %w; %w", err, err2)
			}
			if resp.Rcode != dns.RcodeSuccess {
				return "", false, fmt.Errorf("bad rcode: %s", dns.RcodeToString[resp.Rcode])
			}
			ip = pickFirstARecord(resp.Answer)
			if ip == "" {
				return "", false, errors.New("record not found")
			}
		}
	}

	if dnsCacheEnabled {
		dnsCache.AddWithLifetime(domain, ip, dnsCacheTTL)
	}
	return
}
