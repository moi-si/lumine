package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	dnsClient       *dns.Client
	httpCli         *http.Client
	dnsQuery        func(string, uint16) (string, bool, error)
	dnsCacheEnabled bool
	dnsCache        sync.Map
	dnsCacheTTL     int
)

type dnsCacheEntry struct {
	IP       string
	ExpireAt time.Time
}

func do53Query(domain string, qtype uint16) (string, bool, error) {
	if dnsCacheEnabled {
		lock := getLock(domain)
		lock.Lock()
		defer lock.Unlock()
		v, ok := dnsCache.Load(domain)
		if ok {
			k := v.(dnsCacheEntry)
			if !k.ExpireAt.IsZero() {
				if time.Now().Before(k.ExpireAt) {
					return k.IP, true, nil
				} else {
					dnsCache.Delete(domain)
				}
			}
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	resp, _, err := dnsClient.Exchange(msg, dnsAddr)
	if err != nil {
		return "", false, fmt.Errorf("dns exchange: %s", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", false, fmt.Errorf("bad rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	var ip string
loop:
	for _, ans := range resp.Answer {
		switch qtype {
		case dns.TypeA:
			if record, ok := ans.(*dns.A); ok {
				ip = record.A.String()
				break loop
			}
		case dns.TypeAAAA:
			if record, ok := ans.(*dns.AAAA); ok {
				ip = record.AAAA.String()
				break loop
			}
		}
	}
	if ip == "" {
		return "", false, errors.New("record not found")
	}
	if dnsCacheEnabled {
		var expireAt time.Time
		if dnsCacheTTL == -1 {
			expireAt = time.Time{}
		} else {
			expireAt = time.Now().Add(time.Duration(dnsCacheTTL * int(time.Second)))
		}
		dnsCache.Store(domain, dnsCacheEntry{
			IP:       ip,
			ExpireAt: expireAt,
		})
	}
	return ip, false, nil
}

func dohQuery(domain string, qtype uint16) (string, bool, error) {
	if dnsCacheEnabled {
		lock := getLock(domain)
		lock.Lock()
		defer lock.Unlock()
		v, ok := dnsCache.Load(domain)
		if ok {
			k := v.(dnsCacheEntry)
			if !k.ExpireAt.IsZero() {
				if time.Now().Before(k.ExpireAt) {
					return k.IP, true, nil
				} else {
					dnsCache.Delete(domain)
				}
			}
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", qtype)
	wire, err := msg.Pack()
	if err != nil {
		return "", false, fmt.Errorf("pack dns request: %s", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(wire)
	u := fmt.Sprintf("%s?dns=%s", dnsAddr, b64)
	httpReq, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", false, fmt.Errorf("build http request: %s", err)
	}
	httpReq.Header.Set("Accept", "application/dns-message")
	resp, err := httpCli.Do(httpReq)
	if err != nil {
		return "", false, fmt.Errorf("http request: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("bad http status: %s", resp.Status)
	}
	respWire, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("read http body: %s", err)
	}
	ans := new(dns.Msg)
	if err := ans.Unpack(respWire); err != nil {
		return "", false, fmt.Errorf("unpack dns response: %s", err)
	}
	if ans.Rcode != dns.RcodeSuccess {
		return "", false, fmt.Errorf("bad rcode: %s", dns.RcodeToString[ans.Rcode])
	}

	var ip string
loop:
	for _, ans := range ans.Answer {
		switch qtype {
		case dns.TypeA:
			if record, ok := ans.(*dns.A); ok {
				ip = record.A.String()
				break loop
			}
		case dns.TypeAAAA:
			if record, ok := ans.(*dns.AAAA); ok {
				ip = record.AAAA.String()
				break loop
			}
		}
	}
	if ip == "" {
		return "", false, errors.New("record not found")
	} else {
		if dnsCacheEnabled {
			var expireAt time.Time
			if dnsCacheTTL == -1 {
				expireAt = time.Time{}
			} else {
				expireAt = time.Now().Add(time.Duration(dnsCacheTTL * int(time.Second)))
			}
			dnsCache.Store(domain, dnsCacheEntry{
				IP:       ip,
				ExpireAt: expireAt,
			})
		}
		return ip, false, nil
	}
}

func doubleQuery(domain string, first, second uint16) (ip string, cached bool, err1, err2 error) {
	ip, cached, err1 = dnsQuery(domain, first)
	if err1 != nil {
		ip, cached, err2 = dnsQuery(domain, second)
	}
	return
}
