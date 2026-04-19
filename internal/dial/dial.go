package dial

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	E "github.com/moi-si/lumine/internal/errors"
)

// TCP-only.
var (
	globalIPv4Dialer atomic.Pointer[net.Dialer]
	globalIPv6Dialer atomic.Pointer[net.Dialer]
)

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer *net.Dialer
	if address[0] == '[' {
		dialer = globalIPv6Dialer.Load()
	} else {
		dialer = globalIPv4Dialer.Load()
	}
	return dialer.DialContext(ctx, network, address)
}

func DialTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return DialContext(timeoutCtx, network, address)
}

func DialTCPTimeout(address string, timeout time.Duration) (net.Conn, error) {
	return DialTimeout(context.Background(), "tcp", address, timeout)
}

func laddrMonitor(interval time.Duration, fn func() (net.IP, net.IP, string, error)) {
	ticker := time.NewTicker(interval)
	for {
		<-ticker.C
		ipv4, ipv6, zone, err := fn()
		if err != nil {
			log.Println("Failed to update local address:", err)
			continue
		}
		msg := "Local address updated:"
		if ipv4 != nil {
			globalIPv4Dialer.Store(&net.Dialer{LocalAddr: &net.TCPAddr{IP: ipv4}})
			msg += " ipv4=" + ipv4.String()
		}
		if ipv6 != nil {
			globalIPv6Dialer.Store(&net.Dialer{LocalAddr: &net.TCPAddr{IP: ipv6, Zone: zone}})
			msg += " ipv6=" + ipv6.String()
		}
		if zone != "" {
			msg += " zone=\"" + zone + "\""
		}
		log.Println(msg)
	}
}

var errNoInterfaceWithGateway = E.New("no interface with gateway detected")

func SetLocalAddr(o BindingOption) error {
	var ipv4, ipv6 net.IP
	var zone string
	switch o.Method {
	case MethodOff:
	case MethodSelectInterface:
		interfaces, err := getFilteredInterfaces()
		if err != nil {
			return err
		}
		var (
			selected     *networkInterface
			ok           bool
			zone         string
			hasFixedZone = o.Zone != ""
		)
		if hasFixedZone {
			selected, ok = interfaces.find(o.Zone)
			if !ok {
				return E.New("interface not found: " + o.Zone)
			}
			zone = o.Zone
		} else if o.ManualSelect {
			selected = interfaces.manualSelect()
			zone = selected.name
		} else {
			selected, ok = interfaces.autoSelect()
			if !ok {
				fmt.Fprintln(os.Stderr, "No interface with gateway detected")
				selected = interfaces.manualSelect()
				zone = selected.name
			}
		}
		ipv4, ipv6 = selected.ipv4, selected.ipv6
		if o.UpdateInterval > 0 {
			go laddrMonitor(o.UpdateInterval, func() (net.IP, net.IP, string, error) {
				interfaces, err := getFilteredInterfaces()
				if err != nil {
					return nil, nil, "", err
				}
				var selected *networkInterface
				var ok bool
				if zone == "" {
					selected, ok = interfaces.autoSelect()
					if !ok {
						return nil, nil, "", errNoInterfaceWithGateway
					}
				} else {
					selected, ok = interfaces.find(zone)
					if !ok {
						return nil, nil, "", E.New("interface not found: " + o.Zone)
					}
				}
				return selected.ipv4, selected.ipv6, selected.name, nil
			})
		}
	case MethodDialDetect:
		network := "udp"
		if o.DialTCP {
			network = "tcp"
		}
		var err error
		if o.DialIPv4Target != "" {
			ipv4, _, err = detectByDial(network, o.DialIPv4Target, o.DialTimeout)
			if err != nil {
				return err
			}
		}
		if o.DialIPv6Target != "" {
			ipv6, zone, err = detectByDial(network, o.DialIPv6Target, o.DialTimeout)
			if err != nil {
				return err
			}
		}
		if o.UpdateInterval > 0 {
			go laddrMonitor(o.UpdateInterval, func() (ipv4, ipv6 net.IP, zone string, err error) {
				var err1, err2 error
				if o.DialIPv4Target != "" {
					ipv4, _, err1 = detectByDial(network, o.DialIPv4Target, o.DialTimeout)
				}
				if o.DialIPv6Target != "" {
					ipv6, zone, err2 = detectByDial(network, o.DialIPv6Target, o.DialTimeout)
				}
				err = E.Join(err1, err2)
				return
			})
		}
	case MethodCustom:
		ipv4, ipv6, zone = o.CustomIPv4, o.CustomIPv6, o.CustomZone
	}
	ipv4Dialer, ipv6Dialer := new(net.Dialer), new(net.Dialer)
	if ipv4 != nil {
		ipv4Dialer.LocalAddr = &net.TCPAddr{IP: ipv4}
	}
	if ipv6 != nil {
		ipv6Dialer.LocalAddr = &net.TCPAddr{IP: ipv6, Zone: zone}
	}
	globalIPv4Dialer.Store(ipv4Dialer)
	globalIPv6Dialer.Store(ipv6Dialer)
	return nil
}
