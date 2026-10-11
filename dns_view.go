package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m *model) dnsMatches(e DNSEntry, q string) bool {
	s := strings.ToLower(e.Name + " " + strings.Join(e.Procs, " ") + " " + strings.Join(e.CNAMEs, " "))
	for _, ip := range e.Answers {
		s += " " + ip.String()
	}
	return strings.Contains(s, q)
}

func (m *model) lessDNS(a, b *DNSEntry) bool {
	switch m.sort {
	case sortBytes, sortPkts:
		if a.Count != b.Count {
			return a.Count > b.Count
		}
	case sortAddr:
		return a.Name < b.Name
	}
	if !a.Last.Equal(b.Last) {
		return a.Last.After(b.Last)
	}
	return a.Name < b.Name
}

// dnsNetwork names the organisation behind a lookup's first answer.
func (m model) dnsNetwork(e DNSEntry) string {
	if len(e.Answers) == 0 {
		return ""
	}
	m.res.Enqueue(e.Answers[0])
	hi := m.res.Get(e.Answers[0])
	return firstNonEmpty(hi.Org, hi.ASN)
}

func (m model) renderDNS(b *strings.Builder) {
	start, end := m.window(len(m.dns))
	cols := []col{
		{"LAST", 5, true, 0}, {"COUNT", 6, true, 0}, {"TYPE", 9, false, 3}, {"NAME", 38, false, 0},
		{"NETWORK", 20, false, 2}, {"PROCESS", 16, false, 1}, {"ANSWERS", 16, false, 0},
	}
	var rows [][]string
	var styles []lipgloss.Style
	for i := start; i < end; i++ {
		e := m.dns[i]
		answer := ""
		switch {
		case len(e.Answers) > 0:
			answer = e.Answers[0].String()
			if len(e.Answers) > 1 {
				answer += fmt.Sprintf(" +%d", len(e.Answers)-1)
			}
		case e.Fails > 0:
			answer = "failed"
		case len(e.CNAMEs) > 0:
			answer = "→ " + e.CNAMEs[0]
		}
		rows = append(rows, []string{age(e.Last), fmt.Sprint(e.Count), strings.Join(e.Types, ","), e.Name,
			m.dnsNetwork(e), orDash(strings.Join(e.Procs, ",")), answer})
		st := lipgloss.NewStyle()
		if e.Fails > 0 && len(e.Answers) == 0 {
			st = stErr
		}
		styles = append(styles, st)
	}
	m.renderTable(b, cols, rows, styles, len(m.dns))
}

func (m model) dnsRows(e DNSEntry) []kv2 {
	var answers []string
	for _, ip := range e.Answers {
		m.res.Enqueue(ip)
		hi := m.res.Get(ip)
		a := ip.String()
		if o := firstNonEmpty(hi.Org, hi.ASN); o != "" {
			a += " (" + o + ")"
		}
		answers = append(answers, a)
	}
	fails := ""
	if e.Fails > 0 {
		fails = fmt.Sprint(e.Fails)
	}
	return []kv2{
		{"name", e.Name},
		{"types", strings.Join(e.Types, ", ")},
		{"lookups", fmt.Sprint(e.Count)},
		{"failures", fails},
		{"first", e.First.Format("15:04:05")},
		{"last", e.Last.Format("15:04:05")},
		{"aliases", strings.Join(e.CNAMEs, ", ")},
		{"answers", strings.Join(answers, ", ")},
		{"programs", strings.Join(e.Procs, ", ")},
	}
}

func (m model) aiDNS(e DNSEntry) (string, string) {
	var b strings.Builder
	b.WriteString(m.aiPreamble())
	b.WriteString("Selected item: a domain this machine looked up.\n")
	for _, r := range m.dnsRows(e) {
		if r.v != "" {
			fmt.Fprintf(&b, "%s: %s\n", r.k, r.v)
		}
	}
	b.WriteString("\nWhat is this domain, and why would this machine look it up?")
	return "Ask Claude · " + e.Name, b.String()
}
