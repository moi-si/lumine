package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
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
		return errors.New("invalid mode: " + s)
	}
	return nil
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
		return fmt.Errorf("Invalid bool: %s", s)
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

	NumRecords   int
	NumSegments  int
	OOB          BoolWithDefault
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
		ModMinorVer    BoolWithDefault `json:"mod_minor_ver"`
		SendInterval   *string         `json:"send_Interval"`
		FakeTTL        *int            `json:"fake_ttl"`
		FakeSleep      *string         `json:"fake_sleep"`
		MaxTTL         *int            `json:"max_ttl"`
		Attempts       *int            `json:"attempts"`
		SingleTimeout  *string         `json:"single_timeout"`
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
	p.ModMinorVer = tmp.ModMinorVer

	if tmp.Host != nil && *tmp.Host == "" {
		return errors.New("host cannot be an empty string")
	} else {
		p.Host = tmp.Host
	}

	if tmp.MapTo != nil && *tmp.MapTo == "" {
		return errors.New("map_to cannot be an empty string")
	} else {
		p.MapTo = tmp.MapTo
	}

	if tmp.Port == nil {
		p.Port = -1
	} else if *tmp.Port < 0 || *tmp.Port > 65535 {
		return fmt.Errorf("port %d: outside the valid range", *tmp.Port)
	} else {
		p.Port = int16(*tmp.Port)
	}

	if tmp.HttpStatus == nil {
		p.HttpStatus = -1
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
		p.FakeTTL = -1
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
	if tmp.ConnectTimeout != nil {
		p.ConnectTimeout, err = time.ParseDuration(*tmp.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("parse connect_timeout %s: %w", *tmp.ConnectTimeout, err)
		}
		if p.ConnectTimeout <= 0 {
			return fmt.Errorf("connect_timeout %s: must be greater than 0", *tmp.ConnectTimeout)
		}
	}

	if tmp.SendInterval == nil {
		p.SendInterval = -1
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

	if tmp.SingleTimeout != nil {
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
			if p.ModMinorVer == BoolTrue {
				fields = append(fields, "mod_minor_ver")
			}
		case ModeTTLD:
			if p.FakeTTL == 0 || p.FakeTTL == -1 {
				fields = append(fields, "auto_fake_ttl")
				if p.Attempts != 0 {
					fields = append(fields, "attempts="+strconv.Itoa(p.Attempts))
				}
				if p.MaxTTL != 0 {
					fields = append(fields, "max_ttl="+strconv.Itoa(p.MaxTTL))
				}
				if p.SingleTimeout != 0 {
					fields = append(fields, "single_timeout="+p.SingleTimeout.String())
				}
			} else {
				fields = append(fields, fmt.Sprintf("fake_ttl=%d", p.FakeTTL))
			}
			fields = append(fields, "fake_sleep="+p.FakeSleep.String())
		}
	}
	return strings.Join(fields, " | ")
}

func mergePolicies(policies ...Policy) *Policy {
	merged := Policy{
		HttpStatus:   -1,
		SendInterval: -1,
		FakeTTL:      -1,
	}
	for _, p := range policies {
		if merged.ReplyFirst == BoolUnset && p.ReplyFirst != BoolUnset {
			merged.ReplyFirst = p.ReplyFirst
		}
		if merged.Host == nil && p.Host != nil {
			merged.Host = p.Host
		}
		if merged.MapTo == nil && p.MapTo != nil {
			merged.MapTo = p.MapTo
		}
		if merged.DNSRetry == BoolUnset && p.DNSRetry != BoolUnset {
			merged.DNSRetry = p.DNSRetry
		}
		if merged.IPv6First == BoolUnset && p.IPv6First != BoolUnset {
			merged.IPv6First = p.IPv6First
		}
		if merged.Port == 0 && p.Port != 0 {
			merged.Port = p.Port
		}
		if merged.HttpStatus == -1 && p.HttpStatus != -1 {
			merged.HttpStatus = p.HttpStatus
		}
		if merged.TLS13Only == BoolUnset && p.TLS13Only != BoolUnset {
			merged.TLS13Only = p.TLS13Only
		}
		if merged.Mode == ModeUnknown && p.Mode != ModeUnknown {
			merged.Mode = p.Mode
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
		if merged.ModMinorVer == BoolUnset && p.ModMinorVer != BoolUnset {
			merged.ModMinorVer = p.ModMinorVer
		}
		if merged.SendInterval == -1 && p.SendInterval != -1 {
			merged.SendInterval = p.SendInterval
		}
		if merged.FakeSleep == 0 && p.FakeSleep != 0 {
			merged.FakeSleep = p.FakeSleep
		}
		if merged.FakeTTL == -1 && p.FakeTTL != -1 {
			merged.FakeTTL = p.FakeTTL
		}
		if merged.MaxTTL == 0 && p.MaxTTL != 0 {
			merged.MaxTTL = p.MaxTTL
		}
		if merged.Attempts == 0 && p.Attempts != 0 {
			merged.Attempts = p.Attempts
		}
		if merged.SingleTimeout == 0 && p.SingleTimeout != 0 {
			merged.SingleTimeout = p.SingleTimeout
		}
	}
	return &merged
}
