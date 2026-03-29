package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"network-analyzer/internal/capture"
	"network-analyzer/internal/stats"
	"network-analyzer/internal/ui"
)

func main() {
	iface := flag.String("i", "", "network interface to capture on")
	filter := flag.String("f", "", "BPF filter expression (e.g. 'tcp port 80')")
	flag.Parse()

	if *iface == "" {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error listing interfaces: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("available interfaces:")
		for _, iface := range ifaces {
			fmt.Printf("  %-45s  %s\n", iface.Device, iface.Name)
		}
		fmt.Println("\nuse -i <device> to start")
		os.Exit(0)
	}

	store := stats.NewStore()

	cap, err := capture.New(*iface, *filter, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening interface: %v\n", err)
		os.Exit(1)
	}
	defer cap.Close()

	go cap.Start()

	model := ui.NewModel(store, cap)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error running ui: %v\n", err)
		os.Exit(1)
	}
}