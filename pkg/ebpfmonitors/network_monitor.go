//go:build linux

package ebpfmonitors

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	ebpfmonitors "open-defender/pkg/ebpfmonitors/gobpfs"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir=gobpfs -target bpfel NetworkMonitor bpf/network_monitor.bpf.c -- -I./bpf -O2 -Wall -g

type NetworkEvent struct {
	SrcIP    uint32
	DestPort uint16
}

type networkMonitor struct {
	ctx         context.Context
	cancel      context.CancelFunc
	cfg         config.EbpfNetworkAntireconConfig
	bp          banpool.BanPool
	logFunction func(message string, isNewBan bool)
}

type NetworkMonitor interface {
	Run() error
}

func NewNetworkMonitor(ctx context.Context, cancel context.CancelFunc, cfg config.EbpfNetworkAntireconConfig, bp banpool.BanPool, logFunction func(message string, isNewBan bool)) NetworkMonitor {
	return &networkMonitor{
		ctx:         ctx,
		cancel:      cancel,
		cfg:         cfg,
		bp:          bp,
		logFunction: logFunction,
	}
}

type portSet map[uint16]struct{}

func (nm *networkMonitor) Run() error {
	if nm.cfg.Mode == "disabled" {
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("ebpfmonitors.Run() -> ", err)
	}

	objs := ebpfmonitors.NetworkMonitorObjects{}
	if err := ebpfmonitors.LoadNetworkMonitorObjects(&objs, nil); err != nil {
		return fmt.Errorf("ebpfmonitors.Run() -> %w: %v", ErrCantLoadObjects, err)
	}
	defer objs.Close()

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("ebpfmonitors.Run() -> %w: %v", ErrCantAttachProgram, err)
	}
	var xdpLinks []link.Link
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpNetworkMonitor,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Printf("ebpfmonitors.Run() -> skip XDP on %s: %v", iface.Name, err)
			continue
		}
		xdpLinks = append(xdpLinks, l)
	}

	defer func() {
		for _, l := range xdpLinks {
			l.Close()
		}
	}()
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("ebpfmonitors.Run() -> %w: %v", ErrCantOpenRingbuf, err)
	}
	defer reader.Close()

	stopReading := context.AfterFunc(nm.ctx, func() {
		reader.Close()
	})
	defer stopReading()

	whitelist := portsToSet(nm.cfg.WhitelistPorts)
	blacklist := portsToSet(nm.cfg.BlacklistPorts)

	ipPorts := make(map[uint32]portSet)
	window := max(time.Second, time.Duration(nm.cfg.WindowSeconds)*time.Second)
	windowEnd := time.Now().Add(window)
	reader.SetDeadline(windowEnd)

	for {
		record, err := reader.Read()
		// A busy ring can keep serving records past its deadline.
		if now := time.Now(); !now.Before(windowEnd) {
			ipPorts = make(map[uint32]portSet)
			windowEnd = now.Add(window - now.Sub(windowEnd)%window)
			reader.SetDeadline(windowEnd)
		}
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Println("ebpfmonitors.Run() -> ", err)
			}
			continue
		}

		event, ok := parseEvent(record.RawSample)
		if !ok {
			continue
		}
		if _, banned := whitelist[event.DestPort]; banned {
			continue
		}
		if _, listed := blacklist[event.DestPort]; listed {
			ip := ipString(event.SrcIP)
			nm.report(ip, fmt.Sprintf("network_antirecon -> ip %s hit blacklisted port %d", ip, event.DestPort))
			continue
		}

		ports := ipPorts[event.SrcIP]
		if ports == nil {
			ports = make(portSet)
			ipPorts[event.SrcIP] = ports
		}
		ports[event.DestPort] = struct{}{}

		if nm.cfg.PortsCount > 0 && uint64(len(ports)) >= nm.cfg.PortsCount {
			ip := ipString(event.SrcIP)
			nm.report(ip, fmt.Sprintf("network_antirecon -> ip %s scanned %d ports in %ds window", ip, len(ports), nm.cfg.WindowSeconds))
			delete(ipPorts, event.SrcIP)
		}
	}
}

func (nm *networkMonitor) report(ip string, message string) {
	isNewBan := false
	if nm.cfg.Mode == "blocker" {
		alreadyBanned, err := nm.bp.BanIP(nm.ctx, ip, nm.cfg.BanSeconds)
		if err != nil {
			log.Println(err.Error())
			return
		}
		if alreadyBanned {
			return
		}
		isNewBan = true
	}
	nm.logFunction(message, isNewBan)
}

func portsToSet(ports []uint64) map[uint16]struct{} {
	set := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		set[uint16(port)] = struct{}{}
	}
	return set
}

func parseEvent(sample []byte) (NetworkEvent, bool) {
	if len(sample) < 6 {
		return NetworkEvent{}, false
	}
	// The bpfel program writes host-order fields to the ring buffer.
	return NetworkEvent{
		SrcIP:    binary.LittleEndian.Uint32(sample[0:4]),
		DestPort: binary.LittleEndian.Uint16(sample[4:6]),
	}, true
}

func ipString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
