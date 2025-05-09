package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"sort"

	"zandoli/pkg/sniffer"
)

type ScanResult struct {
	ScanTimestamp      string         `json:"scan_timestamp"`
	Interface          string         `json:"interface"`
	DurationPassiveSec int            `json:"duration_passive_seconds"`
	HostCount          map[string]int `json:"host_count"`
	Passive            []sniffer.Host `json:"passive"`
	Active             []sniffer.Host `json:"active"`
}

func ExportAll(hosts []sniffer.Host, outputDir string, iface string, duration int) error {
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	base := filepath.Join(outputDir, "Results_"+timestamp)

	// Répartir les hôtes
	var passive, active []sniffer.Host
	for _, h := range hosts {
		switch strings.ToLower(h.DetectionMethod) {
		case "passive":
			passive = append(passive, h)
		case "active":
			active = append(active, h)
		}
	}

	// Créer la structure enrichie
	result := ScanResult{
		ScanTimestamp:      time.Now().Format(time.RFC3339),
		Interface:          iface,
		DurationPassiveSec: duration,
		HostCount: map[string]int{
			"total":   len(hosts),
			"passive": len(passive),
			"active":  len(active),
		},
		Passive: passive,
		Active:  active,
	}

	if err := exportJSON(result, base+".json"); err != nil {
		return err
	}
	if err := exportCSV(hosts, base+".csv"); err != nil {
		return err
	}
	if err := exportHTML(hosts, base+".html"); err != nil {
		return err
	}

	return nil
}

func exportJSON(result ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func exportCSV(hosts []sniffer.Host, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"IP", "MAC", "Timestamp", "DetectionMethod"})
	for _, h := range hosts {
		writer.Write([]string{
			h.IP.String(),
			h.MAC.String(),
			h.Timestamp.Format(time.RFC3339),
			h.DetectionMethod,
		})
	}
	return nil
}

func exportHTML(hosts []sniffer.Host, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	countPassive, countActive := 0, 0
	for _, h := range hosts {
		switch strings.ToLower(h.DetectionMethod) {
		case "passive":
			countPassive++
		case "active":
			countActive++
		}
	}

	var title string
	switch {
	case countPassive > 0 && countActive > 0:
		title = "Discovered Hosts (Combined Mode)"
	case countPassive > 0:
		title = "Discovered Hosts (Passive Mode)"
	case countActive > 0:
		title = "Discovered Hosts (Active Mode)"
	default:
		title = "Discovered Hosts"
	}

	fmt.Fprintln(file, "<html><head><meta charset='utf-8'><style>")
	fmt.Fprintln(file, "table {border-collapse: collapse; width: 100%;}")
	fmt.Fprintln(file, "th, td {border: 1px solid #ddd; padding: 8px; font-family: monospace;}")
	fmt.Fprintln(file, "th {background-color: #f2f2f2;}")
	fmt.Fprintln(file, "</style></head><body>")
	fmt.Fprintf(file, "<h2>%s</h2>\n", title)
	fmt.Fprintf(file, "<p>Total: %d | Passive: %d | Active: %d</p>\n", len(hosts), countPassive, countActive)

	fmt.Fprintln(file, "<table>")
	fmt.Fprintln(file, "<tr><th>#</th><th>IP Address</th><th>MAC Address</th><th>Timestamp</th><th>Detection</th><th>Protocols</th></tr>")

	for i, h := range hosts {
		protocols := protocolsToList(h.ProtocolsSeen)
		fmt.Fprintf(file, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			i+1, h.IP.String(), h.MAC.String(), h.Timestamp.Format("2006-01-02 15:04:05"), h.DetectionMethod, strings.Join(protocols, ", "))
	}

	fmt.Fprintln(file, "</table></body></html>")
	return nil
}

func protocolsToList(m map[string]bool) []string {
	var list []string
	for k := range m {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

