package scope

import "net"

// blockedNets contains all IP ranges that must never be contacted:
// RFC1918, loopback, link-local, cloud metadata, IPv6 ULA/link-local.
var blockedNets []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4 private / reserved
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local + AWS metadata
		"0.0.0.0/8",
		"100.64.0.0/10",  // CGN / shared address space
		"192.0.0.0/24",
		"192.0.2.0/24",   // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved
		"255.255.255.255/32",

		// IPv6 private / reserved
		"::1/128",       // loopback
		"fc00::/7",      // ULA
		"fe80::/10",     // link-local
		"ff00::/8",      // multicast
		// NOTE: ::ffff:0:0/96 is NOT listed here — it matches ALL IPv4.
		// IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) is handled by
		// normalizing to IPv4 via To4() before checking.
		"2001:db8::/32", // documentation
		"100::64/128",   // discard
	}

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("bad CIDR in blocklist: " + cidr)
		}
		blockedNets = append(blockedNets, ipNet)
	}
}

// cloudMetadataIPs are specific IPs used by cloud providers for metadata services.
var cloudMetadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // AWS / GCP / Azure
	net.ParseIP("100.100.100.200"), // Alibaba Cloud
	net.ParseIP("fd00:ec2::254"),   // AWS IPv6 metadata
}

// IsBlockedIP returns true if the IP is in a blocked range or is a known
// cloud metadata endpoint.
func IsBlockedIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 to IPv4 for consistent checking
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}

	for _, meta := range cloudMetadataIPs {
		if ip.Equal(meta) {
			return true
		}
	}

	return false
}
