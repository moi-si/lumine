package dial

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	E "github.com/moi-si/lumine/internal/errors"
)

type Method uint8

const (
	MethodOff Method = iota
	MethodSelectInterface
	MethodDialDetect
	MethodCustom
)

func (m *Method) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "off":
		*m = MethodOff
	case "select_interface":
		*m = MethodSelectInterface
	case "dial_detect":
		*m = MethodDialDetect
	case "custom":
		*m = MethodCustom
	default:
		return E.New("invalid method: " + s)
	}
	return nil
}

type BindingOption struct {
	Method         Method
	Zone           string
	UpdateInterval time.Duration
	DialTCP        bool
	DialIPv4Target string
	DialIPv6Target string
	DialTimeout    time.Duration
	CustomIPv4     net.IP
	CustomIPv6     net.IP
	CustomZone     string
}

func (o *BindingOption) UnmarshalJSON(data []byte) (err error) {
	defer func() {
		if err != nil {
			err = E.WithStr("outbound_binding", err)
		}
	}()
	var tmp struct {
		Method         Method `json:"method"`
		Zone           string `json:"zone"`
		UpdateInterval string `json:"update_interval"`
		DialTCP        bool   `json:"dial_tcp"`
		DialIPv4Target string `json:"dial_ipv4_target"`
		DialIPv6Target string `json:"dial_ipv6_target"`
		DialTimeout    string `json:"dial_timeout"`
		CustomIPv4     string `json:"custom_ipv4"`
		CustomIPv6     string `json:"custom_ipv6"`
		CustomZone     string `json:"custom_zone"`
	}
	if err = json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	o.Method = tmp.Method
	switch o.Method {
	case MethodOff:
	case MethodSelectInterface:
		if tmp.UpdateInterval != "" {
			o.UpdateInterval, err = time.ParseDuration(tmp.UpdateInterval)
			if err != nil {
				return fmt.Errorf("parse update_interval %s: %w", tmp.UpdateInterval, err)
			}
		}
		o.Zone = tmp.Zone
	case MethodDialDetect:
		if tmp.UpdateInterval != "" {
			o.UpdateInterval, err = time.ParseDuration(tmp.UpdateInterval)
			if err != nil {
				return fmt.Errorf("parse update_interval %s: %w", tmp.UpdateInterval, err)
			}
		}
		if tmp.DialTimeout != "" {
			o.DialTimeout, err = time.ParseDuration(tmp.DialTimeout)
			if err != nil {
				return fmt.Errorf("parse dial_timeout %s: %w", tmp.DialTimeout, err)
			}
		}
		o.DialTCP = tmp.DialTCP
		o.DialIPv4Target = tmp.DialIPv4Target
		o.DialIPv6Target = tmp.DialIPv6Target
	case MethodCustom:
		o.CustomIPv4 = net.ParseIP(tmp.CustomIPv4)
		o.CustomIPv6 = net.ParseIP(tmp.CustomIPv6)
		o.CustomZone = tmp.CustomZone
		if o.CustomIPv4 == nil && o.CustomIPv6 == nil {
			return E.New("neither custom IPv4 nor IPv6 specified")
		}
	}
	return nil
}
