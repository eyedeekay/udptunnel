// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package udptunnel

import (
	"bytes"
	"context"
	"crypto/md5"
	"log"
	"net"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eyedeekay/udptunnel/common"
	"github.com/eyedeekay/udptunnel/filter"
	"github.com/eyedeekay/udptunnel/logger"
	"github.com/songgao/water"
)

// Tunnel is a pluggable vpn that can use anything that implements net.PacketConn
type Tunnel struct {
	Server        bool
	tunDevName    string
	tunLocalAddr  net.Addr
	tunRemoteAddr net.Addr
	netAddr       net.Addr
	ports         []uint16
	magic         string
	beatInterval  time.Duration
	//sock             net.PacketConn
	setupSock        func(net.Addr) net.PacketConn
	resolve          func() (net.Addr, error)
	updateRemoteAddr func(net.Addr)
	LoadRemoteAddr   func() net.Addr
	writeConn        func(sock net.PacketConn, raddr net.Addr, b []byte, n int, magic [16]byte) (int, error)
	log              udpcommon.Logger

	// RemoteAddr is the address of the remote endpoint and may be
	// arbitrarily updated.
	RemoteAddr atomic.Value

	// testReady and testDrop are used by tests to detect specific events.
	testReady chan<- struct{} // Closed when tunnel is ready
	testDrop  chan<- []byte   // Copy of every dropped packet
}

func (t *Tunnel) defaultSetupSock(netAddr net.Addr) net.PacketConn {
	// Create a new UDP socket.
	host, port, _ := net.SplitHostPort(netAddr.String())
	if port == "" {
		port = "0"
	}
	if !t.Server {
		host = ""
	}
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatalf("error resolving address: %v", err)
	}

	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("error listening on socket: %v", err)
	}
	return sock
}

func (t Tunnel) defaultResolve() (net.Addr, error) {
	return net.ResolveUDPAddr("udp", t.netAddr.String())
}

// Run starts the VPN tunnel over UDP using the provided config and Logger.
// When the context is canceled, the function is guaranteed to block until
// it is fully shutdown.
//
// The channels testReady and testDrop are only used for testing and may be nil.
func (t *Tunnel) Run(ctx context.Context) {
	// Determine the daemon mode from the network address.
	var wg sync.WaitGroup
	defer wg.Wait()

    water.Config conf
	// Create a new tunnel device (requires root privileges).
    if runtime.GOOS == "windows" {
        conf = water.Config{DeviceType: water.TAP}
    }else{
        conf = water.Config{DeviceType: water.TUN}
    }
	if runtime.GOOS == "linux" && t.tunDevName != "" {
		// Use reflect to avoid separate build file for linux-only.
		reflect.ValueOf(&conf).Elem().FieldByName("Name").SetString(t.tunDevName)
	}
	iface, err := water.New(conf)
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	t.log.Printf("created tun device: %v", iface.Name())
	defer iface.Close()
	defer pingIface(t.tunLocalAddr)

	// Setup IP properties.
	switch runtime.GOOS {
	case "linux":
		t.log.Printf("/sbin/ip link set dev %s mtu 1300", iface.Name())
		if err := exec.Command("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", "1300").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
		t.log.Printf("/sbin/ip addr add %s %s", t.tunLocalAddr.String()+"/24 dev", iface.Name())
		if err := exec.Command("/sbin/ip", "addr", "add", t.tunLocalAddr.String()+"/24", "dev", iface.Name()).Run(); err != nil {
			t.log.Fatalf("ip addr error: %v", err)
		}
		t.log.Printf("/sbin/ip link set dev %s up", iface.Name())
		if err := exec.Command("/sbin/ip", "link", "set", "dev", iface.Name(), "up").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
	case "darwin":
		if err := exec.Command("/sbin/ifconfig", iface.Name(), "mtu", "1300", t.tunLocalAddr.String(), t.tunRemoteAddr.String(), "up").Run(); err != nil {
			t.log.Fatalf("ifconfig error: %v", err)
		}
	case "windows":
		t.log.Printf("netsh interface ipv4 add address %s %s 255.255.255.0", iface.Name(), t.tunLocalAddr.String())
		if err := exec.Command("netsh", "interface", "ipv4", "add", "address", iface.Name(), t.tunLocalAddr.String(), "255.255.255.0"); err != nil {
			t.log.Fatalf("netsh error: %v", err)
		}
	default:
		t.log.Fatalf("no tun support for: %v", runtime.GOOS)
	}

	sock := t.setupSock(t.netAddr)
	defer sock.Close()

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435

	if t.testReady != nil {
		close(t.testReady)
	}
	pf := udpfilter.NewPortFilter(t.ports)
	pl := udplogger.NewPacketLogger(ctx, &wg, t.log)

	// On the client, start some goroutines to accommodate for the dynamically
	// changing environment that the client may be in.
	magic := md5.Sum([]byte(t.magic))
	if !t.Server {
		// Since the remote address could change due to updates to DNS,
		// periodically check DNS for a new address.
		raddr, err := t.resolve()
		if err != nil {
			t.log.Fatalf("error resolving address: %v", err)
		}
		t.updateRemoteAddr(raddr)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				raddr, _ := t.resolve()
				if isDone(ctx) {
					return
				}
				t.updateRemoteAddr(raddr)
			}
		}()
        t.log.Printf("Remote Address set")

		// Since the local address could change due to switching interfaces
		// (e.g., switching from cellular hotspot to hardwire ethernet),
		// periodically ping the server to inform it of our new UDP address.
		// Sending a packet with only the magic header is sufficient.
		go func() {
			if t.beatInterval == 0 {
				return
			}
			t.log.Printf("Ticker heartbeat interval: %v", t.beatInterval.Seconds())
			ticker := time.NewTicker(t.beatInterval)
			defer ticker.Stop()
			var prevTxn uint64
			for range ticker.C {
				if isDone(ctx) { // Stop if done.
					t.log.Printf("Context is done")
					return
				}
				raddr := t.LoadRemoteAddr()
				if raddr == nil { // Skip if no remote endpoint.
					t.log.Printf("Remote Endpoint Not found")
					continue
				}
				txn := pl.Stats().Tx.Okay.Count
				if prevTxn == txn { // Only send if there is no outbound traffic
					t.writeConn(sock, raddr, nil, 0, magic)
				}
				prevTxn = txn
			}
		}()
	}

	// Handle outbound traffic.
	wg.Add(1)
	go func() {
		t.log.Printf("out")
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, err := iface.Read(b[len(magic):])
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun read error: %v", err)
			}
			n += copy(b, magic[:])
			p := b[len(magic):n]
			t.log.Printf("Read %d bytes out", n)

			raddr := t.LoadRemoteAddr()
			if pf.Filter(p, udpcommon.OutBound) || raddr == nil {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, udpcommon.OutBound, true)
				continue
			}

			//if _, err := sock.(*net.UDPConn).WriteToUDP(b[:n], raddr.(*net.UDPAddr)); err != nil {
			if _, err := t.writeConn(sock, raddr, b, n, magic); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net write error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			pl.Log(p, udpcommon.OutBound, false)
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		t.log.Printf("in")
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, raddr, err := sock.ReadFrom(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net read error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			t.log.Printf("Read %d bytes in", n)
			if !bytes.HasPrefix(b[:n], magic[:]) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), b[:n]...)
				}
				t.log.Printf("invalid packet from remote address: %v", raddr)
				continue
			}
			p := b[len(magic):n]

			// We assume a matching magic prefix is sufficient to validate
			// that the new IP is really the remote endpoint.
			// We assume that any adversary capable of performing a replay
			// attack already has the power to disrupt communication.
			if t.Server {
				t.updateRemoteAddr(raddr)
			}
			if len(p) == 0 {
				continue // Assume empty packets are a form of pinging
			}

			if pf.Filter(p, udpcommon.InBound) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, udpcommon.InBound, true)
				continue
			}

			if _, err := iface.Write(p); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun write error: %v", err)
			}
			pl.Log(p, udpcommon.InBound, false)
		}
	}()

	<-ctx.Done()
}

func (t *Tunnel) defaultLoadRemoteAddr() net.Addr {
	addr, _ := t.RemoteAddr.Load().(*net.UDPAddr)
	return addr
}

func (t *Tunnel) defaultUpdateRemoteAddr(addr net.Addr) {
	oldAddr := t.LoadRemoteAddr()
	t.log.Printf("Finding new endpoint")
	if addr != nil && (oldAddr == nil || addr.String() != oldAddr.String()) { //|| addr.Zone != oldAddr.Zone) {
		t.RemoteAddr.Store(addr)
		t.log.Printf("switching remote address: %v != %v", addr, oldAddr)
	}
}

func (t *Tunnel) defaultWriteConn(sock net.PacketConn, raddr net.Addr, b []byte, n int, magic [16]byte) (int, error) {
	if n != 0 {
		return sock.(*net.UDPConn).WriteToUDP(b[:n], raddr.(*net.UDPAddr))
	}
	return sock.(*net.UDPConn).WriteToUDP(magic[:], raddr.(*net.UDPAddr))
}

// pingIface sends a broadcast ping to the IP range of the TUN device
// until the TUN device has shutdown.
func pingIface(addr net.Addr) {
	// HACK(dsnet): For reasons I do not understand, closing the TUN device
	// does not cause a pending Read operation to become unblocked and return
	// with some EOF error. As a workaround, we broadcast on the IP range
	// of the TUN device, forcing the Read to unblock with at least one packet.
	// The subsequent call to Read will properly report that it is closed.
	//
	// See https://github.com/songgao/water/issues/22
	go func() {
		addrstring := strings.TrimRight(addr.String(), "0123456798")
		for i := 0; i < 256; i++ {
			cmd := exec.Command("ping", "-c", "1", addrstring+strconv.Itoa(i))
			cmd.Start()
		}
	}()
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// NewTunnel *safely* generates a new Tunnel object using the defaults functions.
func NewTunnel(serverMode bool, tunDevName, tunLocalAddr, tunRemoteAddr, netAddr string, ports []uint16,
	magic string, beatInterval uint, log udpcommon.Logger) *Tunnel {
	localaddr, err := net.ResolveIPAddr("ip", tunLocalAddr)
	if err != nil {
		log.Printf("%s", err)
	}
	remoteaddr, err := net.ResolveIPAddr("ip", tunRemoteAddr)
	if err != nil {
		log.Printf("%s", err)
	}
	netaddr, err := net.ResolveUDPAddr("udp", netAddr)
	if err != nil {
		log.Printf("%s", err)
	}
	tun := Tunnel{
		Server:        serverMode,
		tunDevName:    tunDevName,
		tunLocalAddr:  localaddr,
		tunRemoteAddr: remoteaddr,
		netAddr:       netaddr,
		ports:         ports,
		magic:         magic,
		beatInterval:  time.Second * time.Duration(beatInterval),
		log:           log,
	}
	tun.setupSock = tun.defaultSetupSock
	tun.resolve = tun.defaultResolve
	tun.updateRemoteAddr = tun.defaultUpdateRemoteAddr
	tun.LoadRemoteAddr = tun.defaultLoadRemoteAddr
	tun.writeConn = tun.defaultWriteConn
	return &tun
}

// NewCustomTunnel will create a tunnel using anything that implements the same
// functions as net.UDPConn.
func NewCustomTunnel(
	serverMode bool,
	tunDevName string,
	tunLocalAddr, tunRemoteAddr, netAddr net.Addr,
	ports []uint16,
	magic string,
	beatInterval uint,
	log udpcommon.Logger,
	setupSocket func(net.Addr) net.PacketConn,
	resolver func() (net.Addr, error),
	updateRemoteAddr func(net.Addr),
	LoadRemoteAddr func() net.Addr,
	writeConn func(sock net.PacketConn, raddr net.Addr, b []byte, n int, magic [16]byte) (int, error),
) *Tunnel {
	tun := Tunnel{
		Server:           serverMode,
		tunDevName:       tunDevName,
		tunLocalAddr:     tunLocalAddr,
		tunRemoteAddr:    tunRemoteAddr,
		netAddr:          netAddr,
		ports:            ports,
		magic:            magic,
		beatInterval:     time.Second * time.Duration(beatInterval),
		log:              log,
		setupSock:        setupSocket,
		resolve:          resolver,
		updateRemoteAddr: updateRemoteAddr,
		LoadRemoteAddr:   LoadRemoteAddr,
		writeConn:        writeConn,
	}
	if setupSocket == nil {
		tun.setupSock = tun.defaultSetupSock
	}
	if resolver == nil {
		tun.resolve = tun.defaultResolve
	}
	if updateRemoteAddr == nil {
		tun.updateRemoteAddr = tun.defaultUpdateRemoteAddr
	}
	if LoadRemoteAddr == nil {
		tun.LoadRemoteAddr = tun.defaultLoadRemoteAddr
	}
	if writeConn == nil {
		tun.writeConn = tun.defaultWriteConn
	}
	return &tun
}
