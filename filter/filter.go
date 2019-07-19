// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package udpfilter

import (
	"encoding/binary"
	"log"
	"sync/atomic"
	"time"

	"github.com/eyedeekay/udptunnel/common"
)

// The length of time before entries in the filter map are considered stale.
const expireTimeout = 300

// The current timestamp in seconds. Must be read using atomic operations.
var atomicNow uint64

func init() {
	atomicNow = uint64(time.Now().Unix())
	go func() {
		for range time.Tick(time.Second) {
			atomic.AddUint64(&atomicNow, 1)
		}
	}()
}

var timeNow = func() uint64 {
	return atomic.LoadUint64(&atomicNow)
}

// IPPacket is a byte slice representing an IP Packet
type IPPacket []byte

// Version tells whether the packet is IPv4 or 6
func (ip IPPacket) Version() int {
	if len(ip) > 0 {
		return int(ip[0] >> 4)
	}
	return 0
}

// Protocol tells whether the packet is TCP, UDP, or ICMP
func (ip IPPacket) Protocol() int {
	if len(ip) > 9 && ip.Version() == 4 {
		return int(ip[9])
	}
	return 0
}

// AddressesV4 returns the IPv4 source and destination addresses of the packet
// as byte slices
func (ip IPPacket) AddressesV4() (src, dst [4]byte) {
	if len(ip) >= 20 && ip.Version() == 4 {
		copy(src[:], ip[12:16])
		copy(dst[:], ip[16:20])
	}
	return
}

// Body returns the body of the packet
func (ip IPPacket) Body() []byte {
	if ip.Version() != 4 {
		return nil // No support for IPv6
	}
	n := int(ip[0] & 0x0f)
	if n < 5 || n > 15 || len(ip) < 4*n {
		return nil
	}
	return ip[4*n:]
}

// TransportPacket helps us get from 'slice of bytes being thrown blindly down
// a tunnel' to a structured thing that can be readily validated by getting the
// transport packet from the IP Packet
type TransportPacket []byte

// Ports tells us the ports in use by the TransportPacket
func (tp TransportPacket) Ports() (src, dst uint16) {
	if len(tp) >= 4 {
		src = binary.BigEndian.Uint16(tp[:2])
		dst = binary.BigEndian.Uint16(tp[2:])
	}
	return
}

//PortFilter is used to filter packets running *inside* the VPN.
type PortFilter struct {
	// Last time a packet was transmitted on some ephemeral source port.
	outMap [1 << 16]uint64 // [port]time

	// Last time a packet was received from some ephemeral source port.
	inMap [1 << 16]uint64 // [port]time

	// Set of allowed inbound ports.
	ports map[uint16]bool
}

//NewPortFilter creates a new PortFilter, which is used to filter packets on
//the VPN, which is itself using UDP.
func NewPortFilter(ports []uint16) *PortFilter {
	sf := &PortFilter{ports: make(map[uint16]bool)}
	for _, p := range ports {
		sf.ports[p] = true
	}
	return sf
}

// Filter takes a slice of bytes and a direction, gets the port the slice of
// bytes is going to, compares it to the filter list, and decides whether or not
// to drop the packet.
func (sf *PortFilter) Filter(b []byte, d udpcommon.Direction) (drop bool) {
	// This logic assumes malformed IP packets are rejected by the Linux kernel.
	ip := IPPacket(b)
	if ip.Version() != 4 {
		return true // No support for tunneling IPv6
	}
	if ip.Protocol() != udpcommon.TCP && ip.Protocol() != udpcommon.UDP {
		return ip.Protocol() != udpcommon.ICMP // Always allow ping
	}
	src, dst := TransportPacket(ip.Body()).Ports()
	log.Printf("Ports discovered: %v:%v, %v:%v", sf.ports[src], src, sf.ports[dst], dst)
	if len(sf.ports) > 0 {
		if sf.ports[src] && sf.ports[dst] {
			log.Println("hit blacklisted port")
			return false
		}
	}
	switch d {
	case udpcommon.OutBound:
		if len(sf.ports) > 0 || sf.ports[src] && dst > 0 {
			// Check whether the destination port is somewhere we have received
			// an inbound packet from.
			ts := atomic.LoadUint64(&sf.inMap[dst])
			return timeNow()-ts >= expireTimeout
		}
		if len(sf.ports) > 0 || sf.ports[dst] && src > 0 {
			// Allowed outbound packet, remember the source port so that inbound
			// traffic is allowed to hit that destination port.
			log.Println("Outbound packet filter")
			atomic.StoreUint64(&sf.outMap[src], timeNow())
			return false
		}
	case udpcommon.InBound:
		if len(sf.ports) > 0 || sf.ports[src] && dst > 0 {
			// Check whether the destination port is somewhere we have sent
			// an outbound packet to.
			ts := atomic.LoadUint64(&sf.outMap[dst])
			return timeNow()-ts >= expireTimeout
		}
		if len(sf.ports) > 0 || sf.ports[dst] && src > 0 {
			// Allowed inbound packet, remember the source port so that outbound
			// traffic is allowed to hit that destination port.
			log.Println("Inbound packet filter")
			atomic.StoreUint64(&sf.inMap[src], timeNow())
			return false
		}
	}
	return true
}
