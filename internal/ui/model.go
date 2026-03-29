package ui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"network-analyzer/internal/capture"
	"network-analyzer/internal/stats"
)

var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212"))

	styleLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	styleValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	stylePaused = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	styleProto = map[string]lipgloss.Style{
		"tcp":   lipgloss.NewStyle().Foreground(lipgloss.Color("39")),
		"udp":   lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		"icmp":  lipgloss.NewStyle().Foreground(lipgloss.Color("204")),
		"dns":   lipgloss.NewStyle().Foreground(lipgloss.Color("140")),
		"other": lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
	}

	sparkChars = []rune("▁▂▃▄▅▆▇█")
)

type tickMsg time.Time

type Model struct {
	store    *stats.Store
	cap      *capture.Capturer
	snapshot stats.Snapshot
	width    int
	height   int
}

func NewModel(store *stats.Store, cap *capture.Capturer) Model {
	return Model{store: store, cap: cap}
}

func (m Model) Init() tea.Cmd {
	return tick()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			exportOnQuit(m.snapshot)
			return m, tea.Quit
		case "p", " ":
			if m.cap.Paused() {
				m.cap.Resume()
				m.store.SetPaused(false)
			} else {
				m.cap.Pause()
				m.store.SetPaused(true)
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.snapshot = m.store.Snapshot()
		return m, tick()
	}
	return m, nil
}

func (m Model) View() string {
	if m.width == 0 {
		return "loading..."
	}

	s := m.snapshot

	status := "  live"
	if s.Paused {
		status = stylePaused.Render("  paused")
	}

	title := lipgloss.JoinHorizontal(lipgloss.Center,
		styleHeader.Render("  network traffic analyzer"),
		"  ",
		styleDim.Render(status),
	)

	overview := renderOverview(s)
	protocols := renderProtocols(s)
	spark := renderSparkline(s)
	ports := renderPorts(s)
	srcTable := renderIPTable("top sources", s.TopSrc)
	dstTable := renderIPTable("top destinations", s.TopDst)
	conns := renderConnections(s)

	row1 := lipgloss.JoinHorizontal(lipgloss.Top, overview, "  ", protocols, "  ", spark)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, srcTable, "  ", dstTable, "  ", ports)
	row3 := conns

	help := styleDim.Render("  p = pause/resume   q = quit   (stats exported to traffic.json and traffic.csv on quit)")

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		"",
		row1,
		"",
		row2,
		"",
		row3,
		"",
		help,
	)
}

func renderOverview(s stats.Snapshot) string {
	rows := []string{
		styleHeader.Render("overview"),
		"",
		row("packets", fmt.Sprintf("%d", s.TotalPackets)),
		row("bytes", formatBytes(s.TotalBytes)),
		row("pkt/s", fmt.Sprintf("%.1f", s.PacketsPerSec)),
		row("bw/s", formatBytes(int64(s.BytesPerSec))+"/s"),
	}
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func renderProtocols(s stats.Snapshot) string {
	rows := []string{styleHeader.Render("protocols"), ""}
	order := []string{"tcp", "udp", "dns", "icmp", "other"}
	for _, proto := range order {
		count, ok := s.Protocols[proto]
		if !ok {
			continue
		}
		style := styleProto[proto]
		bar := buildBar(count, s.TotalPackets, 14)
		rows = append(rows, fmt.Sprintf("%s %s %s",
			style.Width(6).Render(proto),
			bar,
			styleDim.Render(fmt.Sprintf("%d", count)),
		))
	}
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func renderSparkline(s stats.Snapshot) string {
	hist := s.BandwidthHist
	rows := []string{styleHeader.Render("bandwidth (60s)"), ""}

	if len(hist) == 0 {
		rows = append(rows, styleDim.Render("no data yet"))
		return styleBorder.Render(strings.Join(rows, "\n"))
	}

	max := 1.0
	for _, v := range hist {
		if v > max {
			max = v
		}
	}

	spark := make([]rune, len(hist))
	for i, v := range hist {
		idx := int((v / max) * float64(len(sparkChars)-1))
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		spark[i] = sparkChars[idx]
	}

	rows = append(rows,
		lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Render(string(spark)),
		"",
		row("peak", formatBytes(int64(max))+"/s"),
		row("now", formatBytes(int64(s.BytesPerSec))+"/s"),
	)
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func renderPorts(s stats.Snapshot) string {
	rows := []string{
		styleHeader.Render("top ports"),
		"",
		fmt.Sprintf("%s %s %s",
			styleLabel.Width(10).Render("port"),
			styleLabel.Width(6).Render("proto"),
			styleLabel.Width(8).Render("packets"),
		),
	}
	for _, p := range s.TopPorts {
		style := styleProto[p.Proto]
		rows = append(rows, fmt.Sprintf("%s %s %s",
			styleValue.Width(10).Render(fmt.Sprintf("%d", p.Port)),
			style.Width(6).Render(p.Proto),
			styleDim.Width(8).Render(fmt.Sprintf("%d", p.Count)),
		))
	}
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func renderIPTable(title string, entries []stats.IPStat) string {
	rows := []string{
		styleHeader.Render(title),
		"",
		fmt.Sprintf("%s %s %s",
			styleLabel.Width(18).Render("ip"),
			styleLabel.Width(10).Render("bytes"),
			styleLabel.Width(8).Render("packets"),
		),
	}
	for _, e := range entries {
		rows = append(rows, fmt.Sprintf("%s %s %s",
			styleValue.Width(18).Render(truncate(e.IP, 17)),
			styleDim.Width(10).Render(formatBytes(e.Bytes)),
			styleDim.Width(8).Render(fmt.Sprintf("%d", e.Count)),
		))
	}
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func renderConnections(s stats.Snapshot) string {
	rows := []string{
		styleHeader.Render("active connections"),
		"",
		fmt.Sprintf("%s %s %s %s",
			styleLabel.Width(26).Render("source"),
			styleLabel.Width(26).Render("destination"),
			styleLabel.Width(8).Render("proto"),
			styleLabel.Width(10).Render("bytes"),
		),
	}
	for _, c := range s.Connections {
		style := styleProto[c.Proto]
		rows = append(rows, fmt.Sprintf("%s %s %s %s",
			styleValue.Width(26).Render(truncate(c.Src, 25)),
			styleDim.Width(26).Render(truncate(c.Dst, 25)),
			style.Width(8).Render(c.Proto),
			styleDim.Width(10).Render(formatBytes(c.Bytes)),
		))
	}
	return styleBorder.Render(strings.Join(rows, "\n"))
}

func exportOnQuit(s stats.Snapshot) {
	exportJSON(s)
	exportCSV(s)
}

func exportJSON(s stats.Snapshot) {
	data := map[string]any{
		"total_packets":   s.TotalPackets,
		"total_bytes":     s.TotalBytes,
		"protocols":       s.Protocols,
		"top_sources":     s.TopSrc,
		"top_destinations": s.TopDst,
		"top_ports":       s.TopPorts,
		"connections":     s.Connections,
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile("traffic.json", b, 0644)
}

func exportCSV(s stats.Snapshot) {
	f, err := os.Create("traffic.csv")
	if err != nil {
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write([]string{"source", "destination", "protocol", "bytes", "packets"})
	for _, c := range s.Connections {
		w.Write([]string{c.Src, c.Dst, c.Proto, fmt.Sprintf("%d", c.Bytes), fmt.Sprintf("%d", c.Count)})
	}
	w.Flush()
}

func row(label, value string) string {
	return fmt.Sprintf("%s  %s", styleLabel.Width(10).Render(label), styleValue.Render(value))
}

func buildBar(val, total int64, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := int(float64(val) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("░", width-filled))
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}