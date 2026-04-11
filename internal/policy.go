package lumine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	log "github.com/moi-si/mylog"
)

const (
	unsetInt    = -1
	unsetString = "-"
)

type SniffOverrideMode uint8

const (
	SniffOverrideUnset = iota
	SniffOverrideOff
	SniffOverrideAlways
	SniffOverridePolicyExists
)

func (m *SniffOverrideMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "off":
		*m = SniffOverrideOff
	case "always":
		*m = SniffOverrideAlways
	case "policy_exists":
		*m = SniffOverridePolicyExists
	default:
		return errors.New("invalid sniff_override: " + s)
	}
	return nil
}

type Mode uint8

const (
	ModeUnknown Mode = iota
	ModeRaw
	ModeDirect
	ModeTLSRF
	ModeTTLD
	ModeBlock
	ModeTLSAlert
	ModeDefault = ModeTLSRF
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
		return errors.New("invalid mode: " + s)
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

type BoolWithDefault uint8

const (
	BoolUnset BoolWithDefault = iota
	BoolFalse
	BoolTrue
)

func (b *BoolWithDefault) UnmarshalJSON(data []byte) error {
	s := string(data)
	switch s {
	case "null":
		*b = BoolUnset
	case "false":
		*b = BoolFalse
	case "true":
		*b = BoolTrue
	default:
		return errors.New("invalid bool: " + s)
	}
	return nil
}

type Policy struct {
	ReplyFirst        BoolWithDefault
	SniffOverrideMode SniffOverrideMode
	DNSMode           DNSMode
	ConnectTimeout    time.Duration
	Host              string
	MapTo             string
	Port              int
	HttpStatus        int
	TLS13Only         BoolWithDefault
	Mode              Mode

	NumRecords   int
	NumSegments  int
	OOB          BoolWithDefault
	OOBEx        BoolWithDefault
	ModMinorVer  BoolWithDefault
	SendInterval time.Duration

	FakeTTL       int
	FakeSleep     time.Duration
	MaxTTL        int
	Attempts      int
	SingleTimeout time.Duration
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var tmp struct {
		SniffOverrideMode SniffOverrideMode `json:"sniff_override"`
		ReplyFirst        BoolWithDefault   `json:"reply_first"`
		ConnectTimeout    *string           `json:"connect_timeout"`
		Host              *string           `json:"host"`
		MapTo             *string           `json:"map_to"`
		Port              *int              `json:"port"`
		DNSMode           DNSMode           `json:"dns_mode"`
		HttpStatus        *int              `json:"http_status"`
		TLS13Only         BoolWithDefault   `json:"tls13_only"`
		Mode              Mode              `json:"mode"`
		NumRecords        *int              `json:"num_records"`
		NumSegments       *int              `json:"num_segs"`
		OOB               BoolWithDefault   `json:"oob"`
		OOBEx             BoolWithDefault   `json:"oob_ex"`
		ModMinorVer       BoolWithDefault   `json:"mod_minor_ver"`
		SendInterval      *string           `json:"send_interval"`
		FakeTTL           *int              `json:"fake_ttl"`
		FakeSleep         *string           `json:"fake_sleep"`
		MaxTTL            *int              `json:"max_ttl"`
		Attempts          *int              `json:"attempts"`
		SingleTimeout     *string           `json:"single_timeout"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	p.SniffOverrideMode = tmp.SniffOverrideMode
	p.ReplyFirst = tmp.ReplyFirst
	p.TLS13Only = tmp.TLS13Only
	p.Mode = tmp.Mode
	p.DNSMode = tmp.DNSMode
	p.OOB = tmp.OOB
	p.OOBEx = tmp.OOBEx
	p.ModMinorVer = tmp.ModMinorVer

	if tmp.Host == nil {
		p.Host = unsetString
	} else if *tmp.Host == unsetString {
		return errors.New("host cannot be `-`")
	} else {
		p.Host = *tmp.Host
	}

	if tmp.MapTo == nil {
		p.MapTo = unsetString
	} else if *tmp.MapTo == unsetString {
		return errors.New("map_to cannot be `-`")
	} else {
		p.MapTo = *tmp.MapTo
	}

	if tmp.Port == nil {
		p.Port = unsetInt
	} else if *tmp.Port < 0 || *tmp.Port > 65535 {
		return fmt.Errorf("port %d: outside the valid range", *tmp.Port)
	} else {
		p.Port = *tmp.Port
	}

	if tmp.HttpStatus == nil {
		p.HttpStatus = unsetInt
	} else if *tmp.HttpStatus < 0 {
		return fmt.Errorf("http_status %d: outside the valid range", *tmp.HttpStatus)
	} else {
		p.HttpStatus = *tmp.HttpStatus
	}

	if tmp.NumRecords != nil {
		if *tmp.NumRecords <= 0 {
			return fmt.Errorf("num_records %d: must be greater than 0", *tmp.NumRecords)
		} else {
			p.NumRecords = *tmp.NumRecords
		}
	}

	if tmp.NumSegments != nil {
		if *tmp.NumSegments == 0 || *tmp.NumSegments < -1 {
			return fmt.Errorf("num_segs %d: outside the valid range", *tmp.NumSegments)
		} else {
			p.NumSegments = *tmp.NumSegments
		}
	}

	if tmp.FakeTTL == nil {
		p.FakeTTL = unsetInt
	} else if *tmp.FakeTTL < 0 || *tmp.FakeTTL > 255 {
		return fmt.Errorf("fake_ttl %d: outside the valid range", *tmp.FakeTTL)
	} else {
		p.FakeTTL = *tmp.FakeTTL
	}

	if tmp.Attempts != nil {
		if *tmp.Attempts < 1 {
			return fmt.Errorf("attempts %d: must be greater than 1", *tmp.Attempts)
		} else {
			p.Attempts = *tmp.Attempts
		}
	}

	if tmp.MaxTTL != nil {
		if *tmp.MaxTTL <= 1 || *tmp.MaxTTL > 255 {
			return fmt.Errorf("max_ttl %d: outside the valid range", *tmp.MaxTTL)
		} else {
			p.MaxTTL = *tmp.MaxTTL
		}
	}

	var err error
	if tmp.ConnectTimeout == nil {
		p.ConnectTimeout = unsetInt
	} else {
		p.ConnectTimeout, err = time.ParseDuration(*tmp.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("parse connect_timeout %s: %w", *tmp.ConnectTimeout, err)
		}
		if p.ConnectTimeout <= 0 {
			return fmt.Errorf("connect_timeout %s: must be greater than 0", *tmp.ConnectTimeout)
		}
	}

	if tmp.SendInterval == nil {
		p.SendInterval = unsetInt
	} else {
		p.SendInterval, err = time.ParseDuration(*tmp.SendInterval)
		if err != nil {
			return fmt.Errorf("parse send_interval %s: %w", *tmp.SendInterval, err)
		}
		if p.SendInterval < 0 {
			return fmt.Errorf("send_interval %s: outside the valid range", *tmp.SendInterval)
		}
	}

	if tmp.FakeSleep != nil {
		p.FakeSleep, err = time.ParseDuration(*tmp.FakeSleep)
		if err != nil {
			return fmt.Errorf("parse fake_sleep %s: %w", *tmp.FakeSleep, err)
		}
		if p.FakeSleep <= 0 {
			return fmt.Errorf("fake_sleep %s: must be greater than 0", *tmp.FakeSleep)
		}
	}

	if tmp.SingleTimeout == nil {
		p.SingleTimeout = unsetInt
	} else {
		p.SingleTimeout, err = time.ParseDuration(*tmp.SingleTimeout)
		if err != nil {
			return fmt.Errorf("parse single_timeout %s: %w", *tmp.SingleTimeout, err)
		}
		if p.SingleTimeout <= 0 {
			return fmt.Errorf("single_timeout %s: must be greater than 0", *tmp.SingleTimeout)
		}
	}

	return nil
}

func (p Policy) String() string {
	fields := make([]string, 0, 11)
	if p.ConnectTimeout != 0 {
		fields = append(fields, "timeout="+p.ConnectTimeout.String())
	}
	if p.Port != unsetInt && p.Port != 0 {
		fields = append(fields, ":"+formatInt(p.Port))
	}
	if p.DNSMode != DNSModeUnknown && (p.Host == "" || p.Host == unsetString) {
		fields = append(fields, p.DNSMode.String())
	}
	if p.HttpStatus > 0 {
		fields = append(fields, "http_status="+formatInt(p.HttpStatus))
	}
	if p.TLS13Only == BoolTrue {
		fields = append(fields, "tls13_only")
	}
	fields = append(fields, p.Mode.String())
	switch p.Mode {
	case ModeTLSRF:
		if p.ModMinorVer == BoolTrue {
			fields = append(fields, "mod_minor_ver")
		}
		if p.NumRecords != unsetInt && p.NumRecords != 1 {
			fields = append(fields, formatInt(p.NumRecords)+" records")
		}
		if p.NumSegments != unsetInt && p.NumSegments != 1 {
			fields = append(fields, formatInt(p.NumSegments)+" segments")
		}
		if p.SendInterval > 0 {
			fields = append(fields, "send_interval="+p.SendInterval.String())
		}
		if p.OOB == BoolTrue {
			fields = append(fields, "oob")
		}
		if p.OOBEx == BoolTrue {
			fields = append(fields, "oob_ex")
		}
	case ModeTTLD:
		if p.FakeTTL == 0 || p.FakeTTL == unsetInt {
			fields = append(fields, "auto_fake_ttl")
			if p.Attempts != 0 {
				fields = append(fields, "attempts="+formatInt(p.Attempts))
			}
			if p.MaxTTL != 0 {
				fields = append(fields, "max_ttl="+formatInt(p.MaxTTL))
			}
			if p.SingleTimeout != 0 {
				fields = append(fields, "single_timeout="+p.SingleTimeout.String())
			}
		} else {
			fields = append(fields, "fake_ttl="+formatInt(p.FakeTTL))
		}
		fields = append(fields, "fake_sleep="+p.FakeSleep.String())
	}
	return strings.Join(fields, ", ")
}

func mergePolicies(policies ...*Policy) *Policy {
	merged := Policy{
		Host:           unsetString,
		MapTo:          unsetString,
		HttpStatus:     unsetInt,
		SendInterval:   unsetInt,
		FakeTTL:        unsetInt,
		ConnectTimeout: unsetInt,
		SingleTimeout:  unsetInt,
	}
	for _, p := range policies {
		if merged.SniffOverrideMode == SniffOverrideUnset && p.SniffOverrideMode != SniffOverrideUnset {
			merged.SniffOverrideMode = p.SniffOverrideMode
		}
		if merged.ReplyFirst == BoolUnset && p.ReplyFirst != BoolUnset {
			merged.ReplyFirst = p.ReplyFirst
		}
		if merged.ConnectTimeout == unsetInt && p.ConnectTimeout != unsetInt {
			merged.ConnectTimeout = p.ConnectTimeout
		}
		if merged.Host == unsetString && p.Host != unsetString {
			merged.Host = p.Host
		}
		if merged.MapTo == unsetString && p.MapTo != unsetString {
			merged.MapTo = p.MapTo
		}
		if merged.Port == 0 && p.Port != 0 {
			merged.Port = p.Port
		}
		if merged.HttpStatus == unsetInt && p.HttpStatus != unsetInt {
			merged.HttpStatus = p.HttpStatus
		}
		if merged.TLS13Only == BoolUnset && p.TLS13Only != BoolUnset {
			merged.TLS13Only = p.TLS13Only
		}
		if merged.Mode == ModeUnknown && p.Mode != ModeUnknown {
			merged.Mode = p.Mode
		}
		if merged.DNSMode == DNSModeUnknown && p.DNSMode != DNSModeUnknown {
			merged.DNSMode = p.DNSMode
		}
		if merged.NumRecords == 0 && p.NumRecords != 0 {
			merged.NumRecords = p.NumRecords
		}
		if merged.NumSegments == 0 && p.NumSegments != 0 {
			merged.NumSegments = p.NumSegments
		}
		if merged.OOB == BoolUnset && p.OOB != BoolUnset {
			merged.OOB = p.OOB
		}
		if merged.OOBEx == BoolUnset && p.OOBEx != BoolUnset {
			merged.OOBEx = p.OOBEx
		}
		if merged.ModMinorVer == BoolUnset && p.ModMinorVer != BoolUnset {
			merged.ModMinorVer = p.ModMinorVer
		}
		if merged.SendInterval == unsetInt && p.SendInterval != unsetInt {
			merged.SendInterval = p.SendInterval
		}
		if merged.FakeSleep == 0 && p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if merged.FakeTTL == unsetInt && p.FakeTTL != unsetInt {
			merged.FakeTTL = p.FakeTTL
		}
		if merged.MaxTTL == 0 && p.MaxTTL != 0 {
			merged.MaxTTL = p.MaxTTL
		}
		if merged.Attempts == 0 && p.Attempts != 0 {
			merged.Attempts = p.Attempts
		}
		if merged.SingleTimeout == unsetInt && p.SingleTimeout != unsetInt {
			merged.SingleTimeout = p.SingleTimeout
		}
	}
	if merged.Mode == ModeUnknown {
		merged.Mode = ModeDefault
	}
	if merged.DNSMode == DNSModeUnknown {
		merged.DNSMode = DNSModeDefault
	}
	return &merged
}

const (
	noRedirectPrefix = "^"
	ipPoolTagPrefix  = "$"
	resolvePrefix    = "?"
)

func genDoHDialFunc() (func(ctx context.Context, network, address string) (net.Conn, error), error) {
	parsedURL, err := url.Parse(dnsAddr)
	if err != nil {
		return nil, wrap("invalid DoH URL", err)
	}
	host := parsedURL.Hostname()
	dohConnPolicy = new(Policy)
	if net.ParseIP(host) != nil {
		var ipPolicy *Policy
		host, ipPolicy, err = ipRedirect(nil, host)
		if ipPolicy == nil {
			dohConnPolicy = &defaultPolicy
		} else {
			dohConnPolicy = mergePolicies(ipPolicy, &defaultPolicy)
		}
		if err != nil {
			return nil, wrap("ip redirect", err)
		}
	} else {
		domainPolicy, foundDomainPolicy := domainMatcher.Find(host)
		if foundDomainPolicy {
			dohConnPolicy = mergePolicies(domainPolicy, &defaultPolicy)
		} else {
			dohConnPolicy = &defaultPolicy
		}
		disableRedirect := strings.HasPrefix(dohConnPolicy.Host, noRedirectPrefix)
		policyHost := dohConnPolicy.Host
		if disableRedirect {
			policyHost = policyHost[1:]
		}
		var selectedHost string
		if policyHost == "" || policyHost == unsetString {
			var foundInHosts bool
			selectedHost, foundInHosts = hostsMatcher.Find(host)
			if foundInHosts {
				disableRedirect = strings.HasPrefix(selectedHost, noRedirectPrefix)
				if disableRedirect {
					selectedHost = selectedHost[1:]
				}
			}
		} else {
			selectedHost = policyHost
		}
		switch {
		case selectedHost == "self":
		case strings.HasPrefix(selectedHost, ipPoolTagPrefix):
			if host, err = getFromIPPool(selectedHost[1:]); err != nil {
				return nil, err
			}
		case strings.HasPrefix(selectedHost, resolvePrefix):
		default:
			host = selectedHost
		}
	}
	switch dohConnPolicy.Mode {
	case ModeBlock, ModeTLSAlert:
		return nil, errors.New("the mode of the DoH cannot be `block`")
	}
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	if dohConnPolicy.Port != unsetInt {
		port = formatInt(dohConnPolicy.Port)
	}
	addr := net.JoinHostPort(host, port)
	dialer := net.Dialer{Timeout: dohConnPolicy.ConnectTimeout}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			return &interceptConn{Conn: conn}, nil
		}
		return nil, err
	}, nil
}

func genPolicy(logger *log.Logger, originHost string, returnWhenPolicyNotExists bool) (dstHost string, p *Policy, failed, blocked, policyNotExists bool) {
	var err error

	if net.ParseIP(originHost) != nil {
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, originHost)
		if err != nil {
			logger.Error("IP redirect:", err)
			return "", nil, true, false, false
		}
		if ipPolicy == nil {
			p = &defaultPolicy
		} else {
			p = mergePolicies(ipPolicy, &defaultPolicy)
		}
		if p.Mode == ModeBlock {
			return "", nil, false, true, false
		}
		return
	}

	domainPolicy, foundDomainPolicy := domainMatcher.Find(originHost)
	if foundDomainPolicy {
		if domainPolicy.Mode == ModeBlock {
			return "", nil, false, true, false
		}
		p = mergePolicies(domainPolicy, &defaultPolicy)
	} else if returnWhenPolicyNotExists {
		return "", nil, false, false, true
	} else {
		p = &defaultPolicy
	}

	disableRedirect := strings.HasPrefix(p.Host, noRedirectPrefix)
	policyHost := p.Host
	if disableRedirect {
		policyHost = policyHost[1:]
	}
	var selectedHost string
	var foundInHosts bool
	if policyHost == "" || policyHost == unsetString {
		selectedHost, foundInHosts = hostsMatcher.Find(originHost)
		switch selectedHost {
		case "", unsetString:
			var cached bool
			dstHost, cached, err = dnsResolve(originHost, p.DNSMode)
			if err != nil {
				logger.Error("Resolve", originHost+":", err)
				return "", nil, true, false, false
			}
			var logPrefix string
			if cached {
				logPrefix = "DNS (cached):"
			} else {
				logPrefix = "DNS:"
			}
			logger.Info(logPrefix, originHost, "->", dstHost)
		default:
			disableRedirect = strings.HasPrefix(selectedHost, noRedirectPrefix)
			if disableRedirect {
				selectedHost = selectedHost[1:]
			}
		}
	} else {
		selectedHost = policyHost
	}

	if dstHost == "" {
		var logPrefix string
		if foundInHosts {
			logPrefix = "Host (from hosts):"
		} else {
			logPrefix = "Host:"
		}
		switch {
		case selectedHost == "self":
			dstHost = originHost
			logger.Info(logPrefix, originHost)
		case strings.HasPrefix(selectedHost, ipPoolTagPrefix):
			if dstHost, err = getFromIPPool(selectedHost[1:]); err != nil {
				logger.Error(err)
				return "", nil, true, false, false
			}
			logger.Info(logPrefix, selectedHost, "->", dstHost)
		case strings.HasPrefix(selectedHost, resolvePrefix):
			selectedHost = selectedHost[1:]
			var cached bool
			dstHost, cached, err = dnsResolve(selectedHost, p.DNSMode)
			if err != nil {
				logger.Error("Resolve", selectedHost+":", err)
				return "", nil, true, false, false
			}
			var logPrefix string
			if cached {
				logPrefix = "DNS (cached):"
			} else {
				logPrefix = "DNS:"
			}
			logger.Info(logPrefix, originHost, "->", selectedHost, "->", dstHost)
		default:
			dstHost = selectedHost
			logger.Info(logPrefix, dstHost)
		}
	}

	if !disableRedirect {
		var ipPolicy *Policy
		dstHost, ipPolicy, err = ipRedirect(logger, dstHost)
		if err != nil {
			logger.Info("IP redirect:", err)
			return "", nil, true, false, false
		}
		if ipPolicy != nil {
			if foundDomainPolicy {
				p = mergePolicies(domainPolicy, ipPolicy, &defaultPolicy)
			} else {
				p = mergePolicies(ipPolicy, &defaultPolicy)
			}
			if p.Mode == ModeBlock {
				return "", nil, false, true, false
			}
		}
	}

	return
}
