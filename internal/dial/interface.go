package dial

import (
	"fmt"
	"log"
	"net"

	E "github.com/moi-si/lumine/internal/errors"
	F "github.com/moi-si/lumine/internal/format"
)

type networkInterface struct {
	index   int
	name    string
	gateway string
	ipv4    net.IP
	ipv6    net.IP
}

type networkInterfaces []networkInterface

var errNoInterface = E.New("no interface detected")

func getFilteredInterfaces() (networkInterfaces, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, E.WithStr("list network interfaces", err)
	}

	interfaces := make([]networkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Println("Get unicast interface for", iface.Name+":", err)
			continue
		}

		var ipv4, ipv6 net.IP
		for _, addr := range addrs {
			if ipv4 != nil && ipv6 != nil {
				break
			}
			ipNet, isIPNet := addr.(*net.IPNet)
			if !isIPNet {
				continue
			}
			ip := ipNet.IP
			if ip.IsLinkLocalUnicast() {
				continue
			}
			isIPv4, isIPv6 := ip.To4() != nil, ip.To16() != nil
			if ipv4 == nil && isIPv4 {
				ipv4 = ip
			} else if ipv6 == nil && !isIPv4 && isIPv6 {
				ipv6 = ip
			}
		}

		if ipv4 == nil && ipv6 == nil {
			continue
		}

		interfaces = append(interfaces, networkInterface{
			index:   iface.Index,
			name:    iface.Name,
			gateway: getGatewayForInterface(iface.Index),
			ipv4:    ipv4,
			ipv6:    ipv6,
		})
	}
	if len(interfaces) == 0 {
		return nil, errNoInterface
	}
	return interfaces, nil
}

func (ifaces networkInterfaces) find(name string) (*networkInterface, bool) {
	for _, iface := range ifaces {
		if iface.name == name {
			return &iface, true
		}
	}
	return nil, false
}

func (ifaces networkInterfaces) autoSelect() (*networkInterface, bool) {
	for _, iface := range ifaces {
		if iface.gateway != "" && iface.ipv4 != nil && iface.ipv4.IsPrivate() {
			return &iface, true
		}
	}
	for _, iface := range ifaces {
		if iface.gateway != "" && iface.ipv4 != nil {
			return &iface, true
		}
	}
	return nil, false
}

func (ifaces networkInterfaces) manualSelect() *networkInterface {
	fmt.Println("\nAvalable Interfaces:")
	for i, iface := range ifaces {
		msg := F.Concat("[", i, "] ", iface.name)
		if iface.gateway != "" {
			msg += " via " + iface.gateway
		}
		msg += ":"
		if iface.ipv4 != nil {
			msg += " ipv4=" + iface.ipv4.String()
		}
		if iface.ipv6 != nil {
			msg += " ipv6=" + iface.ipv6.String()
		}
		fmt.Println(msg)
	}

	length := len(ifaces)
	for {
		fmt.Print(F.Concat("Select index [0-", length-1, "]: "))
		var i int
		_, err := fmt.Scanln(&i)
		if err == nil && i >= 0 && i < length {
			return &ifaces[i]
		}
		fmt.Println("Invalid index")
	}
}
