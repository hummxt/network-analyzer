package capture

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"network-analyzer/internal/stats"
)

type Capturer struct {
	handle *pcap.Handle
	store  *stats.Store
	paused bool
}

type Interface struct {
	Device string
	Name   string
}

func ListInterfaces() ([]Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	sysIfaces, _ := net.Interfaces()
	guidToName := make(map[string]string)
	for _, iface := range sysIfaces {
		guidToName[iface.Name] = iface.Name
	}

	result := make([]Interface, 0, len(devices))
	for _, d := range devices {
		name := d.Description
		if name == "" {
			name = d.Name
		}
		result = append(result, Interface{Device: d.Name, Name: name})
	}
	return result, nil
}

func New(iface, filter string, store *stats.Store) (*Capturer, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, err
		}
	}
	return &Capturer{handle: handle, store: store}, nil
}

func (c *Capturer) Start() {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for packet := range src.Packets() {
		if !c.paused {
			c.process(packet)
		}
	}
}

func (c *Capturer) Pause() { c.paused = true }
func (c *Capturer) Resume() { c.paused = false }
func (c *Capturer) Paused() bool { return c.paused }
func (c *Capturer) Close() { c.handle.Close() }

func (c *Capturer) process(packet gopacket.Packet) {
	meta := packet.Metadata()
	size := int64(meta.CaptureLength)

	proto := "other"
	var srcIP, dstIP string
	var srcPort, dstPort uint16

	if net := packet.NetworkLayer(); net != nil {
		srcIP = net.NetworkFlow().Src().String()
		dstIP = net.NetworkFlow().Dst().String()
	}

	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		proto = "tcp"
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		proto = "udp"
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		proto = "icmp"
	} else if packet.Layer(layers.LayerTypeDNS) != nil {
		proto = "dns"
	}

	c.store.Record(stats.Packet{
		Size:     size,
		Proto:    proto,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	})
}

func FormatInterface(iface Interface) string {
	return fmt.Sprintf("%-20s  %s", shortGUID(iface.Device), iface.Name)
}

func shortGUID(device string) string {
	if len(device) > 20 {
		return "..." + device[len(device)-17:]
	}
	return device
}