package export

import (
	"encoding/csv"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"time"
	"strings"

	"zandoli/pkg/sniffer"
)

type ScanResult struct {
	ScanTimestamp        string            `json:"scan_timestamp"`
	Interface            string            `json:"interface"`
	DurationPassiveSec   int               `json:"duration_passive_seconds"`
	HostCount            map[string]int    `json:"host_count"`
	Passive              []sniffer.Host    `json:"passive"`
	Active               []sniffer.Host    `json:"active"`
}

func ExportAll(hosts []sniffer.Host, outputDir string, iface string, duration int) error {
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	base := filepath.Join(outputDir, "Passive_"+timestamp)

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

	const tmpl = `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Zandoli - Passive Scan Report</title>
		<style>
			body { font-family: sans-serif; padding: 20px; background: #f9f9f9; }
			h2 { color: #2c3e50; }
			table { border-collapse: collapse; width: 100%; }
			th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
			th { background-color: #f0f0f0; }
			tr:nth-child(even) { background-color: #fdfdfd; }
			.mac { font-family: monospace; }
			.detmethod { font-style: italic; color: #888; }
		</style>
	</head>
	<body>
	<h2>Discovered Hosts (Passive Mode)</h2>
	<p>Total: {{len .}}</p>
	<table>
		<tr><th>#</th><th>IP Address</th><th>MAC Address</th><th>Timestamp</th><th>Detection</th></tr>
		{{range $i, $h := .}}
		<tr>
			<td>{{add $i 1}}</td>
			<td>{{$h.IP}}</td>
			<td class="mac">{{$h.MAC}}</td>
			<td>{{$h.Timestamp.Format "2006-01-02 15:04:05"}}</td>
			<td class="detmethod">{{$h.DetectionMethod}}</td>
		</tr>
		{{end}}
	</table>
	</body>
	</html>
	`

	t := template.New("report").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	})
	t = template.Must(t.Parse(tmpl))
	return t.Execute(file, hosts)
}
