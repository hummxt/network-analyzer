package stats

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type Packet struct {
	Size    int64
	Proto   string
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type IPStat struct {
	IP    string
	Bytes int64
	Count int64
}

type PortStat struct {
	Port  uint16
	Proto string
	Bytes int64
	Count int64
}

type Connection struct {
	Src   string
	Dst   string
	Proto string
	Bytes int64
	Count int64
}

type Snapshot struct {
	TotalPackets  int64
	TotalBytes    int64
	PacketsPerSec float64
	BytesPerSec   float64
	Protocols     map[string]int64
	TopSrc        []IPStat
	TopDst        []IPStat
	TopPorts      []PortStat
	Connections   []Connection
	BandwidthHist []float64
	Paused        bool
}

type Store struct {
	mu           sync.Mutex
	totalPackets int64
	totalBytes   int64
	protocols    map[string]int64
	srcIPs       map[string]*IPStat
	dstIPs       map[string]*IPStat
	ports        map[string]*PortStat
	conns        map[string]*Connection
	lastTick     time.Time
	tickPackets  int64
	tickBytes    int64
	pps          float64
	bps          float64
	bwHistory    []float64
	paused       bool
}

func NewStore() *Store {
	return &Store{
		protocols: make(map[string]int64),
		srcIPs:    make(map[string]*IPStat),
		dstIPs:    make(map[string]*IPStat),
		ports:     make(map[string]*PortStat),
		conns:     make(map[string]*Connection),
		lastTick:  time.Now(),
		bwHistory: make([]float64, 0, 60),
	}
}

func (s *Store) SetPaused(v bool) {
	s.mu.Lock()
	s.paused = v
	s.mu.Unlock()
}

func (s *Store) Record(p Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalPackets++
	s.totalBytes += p.Size
	s.tickPackets++
	s.tickBytes += p.Size
	s.protocols[p.Proto]++

	if p.SrcIP != "" {
		if e, ok := s.srcIPs[p.SrcIP]; ok {
			e.Bytes += p.Size
			e.Count++
		} else {
			s.srcIPs[p.SrcIP] = &IPStat{IP: p.SrcIP, Bytes: p.Size, Count: 1}
		}
	}

	if p.DstIP != "" {
		if e, ok := s.dstIPs[p.DstIP]; ok {
			e.Bytes += p.Size
			e.Count++
		} else {
			s.dstIPs[p.DstIP] = &IPStat{IP: p.DstIP, Bytes: p.Size, Count: 1}
		}
	}

	if p.DstPort > 0 {
		key := fmt.Sprintf("%d/%s", p.DstPort, p.Proto)
		if e, ok := s.ports[key]; ok {
			e.Bytes += p.Size
			e.Count++
		} else {
			s.ports[key] = &PortStat{Port: p.DstPort, Proto: p.Proto, Bytes: p.Size, Count: 1}
		}
	}

	if p.SrcIP != "" && p.DstIP != "" {
		key := fmt.Sprintf("%s:%d->%s:%d/%s", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Proto)
		if e, ok := s.conns[key]; ok {
			e.Bytes += p.Size
			e.Count++
		} else {
			src := fmt.Sprintf("%s:%d", p.SrcIP, p.SrcPort)
			dst := fmt.Sprintf("%s:%d", p.DstIP, p.DstPort)
			s.conns[key] = &Connection{Src: src, Dst: dst, Proto: p.Proto, Bytes: p.Size, Count: 1}
		}
	}
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastTick).Seconds()
	if elapsed > 0 {
		s.pps = float64(s.tickPackets) / elapsed
		s.bps = float64(s.tickBytes) / elapsed
		s.tickPackets = 0
		s.tickBytes = 0
		s.lastTick = now

		s.bwHistory = append(s.bwHistory, s.bps)
		if len(s.bwHistory) > 60 {
			s.bwHistory = s.bwHistory[len(s.bwHistory)-60:]
		}
	}

	hist := make([]float64, len(s.bwHistory))
	copy(hist, s.bwHistory)

	protos := make(map[string]int64, len(s.protocols))
	for k, v := range s.protocols {
		protos[k] = v
	}

	return Snapshot{
		TotalPackets:  s.totalPackets,
		TotalBytes:    s.totalBytes,
		PacketsPerSec: s.pps,
		BytesPerSec:   s.bps,
		Protocols:     protos,
		TopSrc:        topNIP(s.srcIPs, 8),
		TopDst:        topNIP(s.dstIPs, 8),
		TopPorts:      topNPorts(s.ports, 8),
		Connections:   topNConns(s.conns, 10),
		BandwidthHist: hist,
		Paused:        s.paused,
	}
}

func topNIP(m map[string]*IPStat, n int) []IPStat {
	list := make([]IPStat, 0, len(m))
	for _, v := range m {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Bytes > list[j].Bytes })
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func topNPorts(m map[string]*PortStat, n int) []PortStat {
	list := make([]PortStat, 0, len(m))
	for _, v := range m {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func topNConns(m map[string]*Connection, n int) []Connection {
	list := make([]Connection, 0, len(m))
	for _, v := range m {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Bytes > list[j].Bytes })
	if len(list) > n {
		list = list[:n]
	}
	return list
}