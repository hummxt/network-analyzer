# network-analyzer

A real-time terminal tool that captures and analyzes live network traffic on your machine.

## what it does

- Captures live packets on any network interface
- Shows traffic speed in packets/sec and bytes/sec
- Breaks traffic down by protocol: TCP, UDP, DNS, ICMP
- Tracks the top source and destination IPs by volume
- Tracks the most active ports
- Shows every active connection as src:port to dst:port
- Draws a live bandwidth graph for the last 60 seconds
- Exports all captured data to traffic.json and traffic.csv when you quit

## requirements

- Go 1.21 or higher
- Npcap installed (download from https://npcap.com, enable WinPcap compatibility mode during install)
- Run as administrator for packet capture

## setup
```bash
go mod tidy
go build -o network-analyzer.exe ./cmd/main.go
```

## usage

List your network interfaces:
```bash
.\network-analyzer.exe
```

Start capturing:
```bash
.\network-analyzer.exe -i "\Device\NPF_{YOUR-GUID-HERE}"
```

Capture only specific traffic using a filter:
```bash
.\network-analyzer.exe -i "\Device\NPF_{YOUR-GUID-HERE}" -f "tcp port 443"
```

## controls

| key | action |
|-----|--------|
| p or space | pause and resume capture |
| q | quit and export data |

## output files

When you quit, two files are written to the same folder:

- traffic.json — full session summary including top IPs, ports, and connections
- traffic.csv — all captured connections in a spreadsheet-friendly format

## project layout
```
cmd/main.go                  entry point
internal/capture/capture.go  packet capture and classification
internal/stats/store.go      metrics tracking and snapshots
internal/ui/model.go         terminal interface
```