package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcTable maps local sockets to the processes that own them by reading
// /proc/net/{tcp,udp}{,6} for port->inode and /proc/*/fd for inode->pid.
// Only processes of the same user are visible without extra privileges.
type ProcTable struct {
	mu          sync.Mutex
	byPort      map[portKey]string
	lastRefresh time.Time
	refreshing  bool
	root        string // "/proc", overridable for tests
}

type portKey struct {
	proto string
	port  uint16
}

func NewProcTable() *ProcTable {
	return &ProcTable{byPort: map[portKey]string{}, root: "/proc"}
}

// Lookup returns "name(pid)" for the process bound to the local port, or "".
// A miss triggers a background refresh at most twice a second, and the table
// is rebuilt every 5 s regardless so reused ports do not keep a stale owner.
func (t *ProcTable) Lookup(proto string, port uint16) string {
	if t == nil || port == 0 || (proto != "TCP" && proto != "UDP") {
		return ""
	}
	t.mu.Lock()
	name, ok := t.byPort[portKey{proto, port}]
	since := time.Since(t.lastRefresh)
	kick := !t.refreshing && ((!ok && since > 500*time.Millisecond) || since > 5*time.Second)
	if kick {
		t.refreshing = true
	}
	t.mu.Unlock()
	if kick {
		go t.refresh()
	}
	return name
}

func (t *ProcTable) refresh() {
	table := t.scan()
	t.mu.Lock()
	t.byPort = table
	t.lastRefresh = time.Now()
	t.refreshing = false
	t.mu.Unlock()
}

// scan builds a fresh port->process table.
func (t *ProcTable) scan() map[portKey]string {
	inodes := map[uint64]portKey{}
	for _, f := range []struct{ file, proto string }{{"tcp", "TCP"}, {"tcp6", "TCP"}, {"udp", "UDP"}, {"udp6", "UDP"}} {
		parseProcNet(filepath.Join(t.root, "net", f.file), f.proto, inodes)
	}
	out := map[portKey]string{}
	if len(inodes) == 0 {
		return out
	}
	pids, err := os.ReadDir(t.root)
	if err != nil {
		return out
	}
	for _, d := range pids {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || !d.IsDir() {
			continue
		}
		fdDir := filepath.Join(t.root, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			key, ok := inodes[ino]
			if !ok {
				continue
			}
			if name == "" {
				name = procName(t.root, d.Name(), pid)
			}
			out[key] = name
		}
	}
	return out
}

func procName(root, dir string, pid int) string {
	b, err := os.ReadFile(filepath.Join(root, dir, "comm"))
	if err != nil {
		return "pid " + strconv.Itoa(pid)
	}
	return strings.TrimSpace(string(b)) + "(" + strconv.Itoa(pid) + ")"
}

// parseProcNet reads one /proc/net table: columns are
// sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
func parseProcNet(path, proto string, inodes map[uint64]portKey) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		_, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		ino, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || ino == 0 {
			continue
		}
		inodes[ino] = portKey{proto, uint16(port)}
	}
}
