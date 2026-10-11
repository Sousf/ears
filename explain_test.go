package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/option"
	tea "github.com/charmbracelet/bubbletea"
)

type fakeAPI struct {
	mu     sync.Mutex
	body   map[string]any
	beta   string
	reply  []string
	stop   string
	status int
	srv    *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{stop: "end_turn", reply: []string{"This is ", "an HTTPS ", "connection."}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		_ = json.Unmarshal(raw, &f.body)
		f.beta = r.Header.Get("anthropic-beta")
		status, reply, stop := f.status, f.reply, f.stop
		f.mu.Unlock()
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprint(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		ev := func(name, data string) { fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data) }
		ev("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":1}}}`)
		ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		for _, s := range reply {
			b, _ := json.Marshal(s)
			ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(b)+`}}`)
		}
		ev("content_block_stop", `{"type":"content_block_stop","index":0}`)
		ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"`+stop+`","stop_sequence":null},"usage":{"output_tokens":5}}`)
		ev("message_stop", `{"type":"message_stop"}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) explainer() *Explainer {
	return NewExplainer("claude-opus-5-5", option.WithBaseURL(f.srv.URL), option.WithAPIKey("test"), option.WithMaxRetries(0))
}

func collect(t *testing.T, ch <-chan aiMsg) (string, error) {
	t.Helper()
	var b strings.Builder
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				t.Fatal("channel closed without done")
			}
			b.WriteString(m.text)
			if m.done {
				return b.String(), m.err
			}
		case <-timeout:
			t.Fatal("timed out")
		}
	}
}

func TestExplainerStreams(t *testing.T) {
	f := newFakeAPI(t)
	text, err := collect(t, f.explainer().Start(t.Context(), 1, "What is this flow?"))
	if err != nil || text != "This is an HTTPS connection." {
		t.Fatalf("text=%q err=%v", text, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.body["model"] != "claude-opus-5-5" || f.body["fallbacks"] != "default" || f.body["stream"] != true {
		t.Fatalf("request body: %v", f.body)
	}
	if oc, _ := f.body["output_config"].(map[string]any); oc["effort"] != "medium" {
		t.Fatalf("effort: %v", f.body["output_config"])
	}
	if !strings.Contains(f.beta, "server-side-fallback-2026-07-01") {
		t.Fatalf("beta header: %q", f.beta)
	}
	if _, ok := f.body["thinking"]; ok {
		t.Fatalf("thinking must be left unset: %v", f.body["thinking"])
	}
}

func TestExplainerRefusalAndErrors(t *testing.T) {
	f := newFakeAPI(t)
	f.stop = "refusal"
	text, err := collect(t, f.explainer().Start(t.Context(), 1, "q"))
	if err != nil || !strings.Contains(text, "declined") {
		t.Fatalf("refusal: text=%q err=%v", text, err)
	}
	f.mu.Lock()
	f.status = 401
	f.mu.Unlock()
	_, err = collect(t, f.explainer().Start(t.Context(), 2, "q"))
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Fatalf("401: %v", err)
	}
}

func TestAskClaudeUI(t *testing.T) {
	f := newFakeAPI(t)
	agg, res := testAgg(t)
	feed(t, agg,
		dnsFrame(t, "1.1.1.1", "192.168.1.117", true),
		tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "SYN", nil),
		tcpFrame(t, "203.0.113.5", "192.168.1.117", 443, 40000, "SYN,ACK", nil),
		tcpFrame(t, "192.168.1.117", "203.0.113.5", 40000, 443, "PSH,ACK", clientHello("api.example.com")),
	)
	m := newModel(agg, res, &Capture{}, make(chan error), "wlan0", "")
	mm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = mm.(model)
	mm, _ = m.Update(tickMsg(time.Now()))
	m = mm.(model)

	// Without -ai, the key explains how to enable it and sends nothing.
	mm, cmd := m.Update(key("a"))
	m = mm.(model)
	if m.overlay == nil || !strings.Contains(m.View(), "Start with -ai") || cmd != nil {
		t.Fatalf("disabled panel:\n%s", m.View())
	}
	mm, _ = m.Update(key("esc"))
	m = mm.(model)

	m.explain = f.explainer()
	for i, fl := range m.flows {
		if fl.Key.RemotePort == 443 {
			m.cursor = i
		}
	}
	mm, cmd = m.Update(key("a"))
	m = mm.(model)
	if m.overlay == nil || !m.overlay.ai || cmd == nil {
		t.Fatal("ask panel did not open")
	}
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			break
		}
		mm, cmd = m.Update(msg)
		m = mm.(model)
	}
	out := m.View()
	if !strings.Contains(out, "This is an HTTPS connection.") || !strings.Contains(out, "claude-opus-5-5 via the API · may be wrong") {
		t.Fatalf("answer panel:\n%s", out)
	}
	// v shows the exact prompt, which describes the selected flow.
	mm, _ = m.Update(key("v"))
	m = mm.(model)
	out = strings.Join(m.overlay.lines, "\n")
	for _, want := range []string{"203.0.113.5 port 443 (https)", "api.example.com", "192.168.1.117", "SYN,ACK"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sent prompt missing %q:\n%s", want, out)
		}
	}
	mm, _ = m.Update(key("esc"))
	m = mm.(model)
	if m.overlay != nil {
		t.Fatal("panel did not close")
	}
	// Prompts build for every view without panicking.
	m.setView(viewHosts)
	m.rebuild()
	_, p := m.aiHost(m.hosts[0])
	m.setView(viewPackets)
	m.rebuild()
	_, p2 := m.aiPacket(m.pkts[0])
	if !strings.Contains(p, "remote host") || !strings.Contains(p2, "Decoded layers") || !strings.Contains(p2, "First bytes in hex") {
		t.Fatalf("host/packet prompts:\n%s\n---\n%s", p, p2)
	}
	_, p3 := m.aiNotice(Notice{T: time.Now(), Kind: "inbound", Text: "203.0.113.5 (public) opened a TCP connection to local port 22"})
	if !strings.Contains(p3, "Address 203.0.113.5") {
		t.Fatalf("notice prompt:\n%s", p3)
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("one two three four five six\n\n- a list item that wraps around", 20)
	want := []string{"one two three four", "five six", "", "- a list item that", "  wraps around"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

// fakeClaude writes a script that mimics `claude -p --output-format stream-json`.
func fakeClaude(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/claude"
	script := "#!/bin/sh\ncat > " + dir + "/stdin\necho \"$@\" > " + dir + "/args\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const ccOK = `cat <<'X'
{"type":"system","subtype":"init"}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Port 443 "}}}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"is HTTPS."}}}
{"type":"assistant","message":{"content":[{"type":"text","text":"Port 443 is HTTPS."}]}}
{"type":"stream_event","event":{"type":"message_delta","delta":{"stop_reason":"end_turn"}}}
{"type":"result","subtype":"success","is_error":false,"result":"Port 443 is HTTPS."}
X
`

func TestClaudeCodeBackend(t *testing.T) {
	bin := fakeClaude(t, ccOK)
	cc := &ClaudeCode{bin: bin}
	text, err := collect(t, cc.Start(t.Context(), 1, "What is port 443?"))
	if err != nil || text != "Port 443 is HTTPS." {
		t.Fatalf("text=%q err=%v", text, err)
	}
	dir := bin[:len(bin)-len("/claude")]
	stdin, _ := os.ReadFile(dir + "/stdin")
	args, _ := os.ReadFile(dir + "/args")
	if string(stdin) != "What is port 443?" {
		t.Fatalf("stdin: %q", stdin)
	}
	for _, want := range []string{"-p", "--output-format stream-json", "--include-partial-messages", "--tools  --no-session-persistence", "--system-prompt You explain network traffic"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("args missing %q: %s", want, args)
		}
	}
	if strings.Contains(string(args), "--model") {
		t.Fatalf("model passed without -ai-model: %s", args)
	}
	if cc.Label() != "Claude Code" || (&ClaudeCode{model: "claude-sonnet-5-5"}).Label() != "claude-sonnet-5-5 via Claude Code" {
		t.Fatal("labels")
	}

	// Error result and non-zero exit with a login message.
	bin = fakeClaude(t, `echo '{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Credit balance too low"}'`)
	if _, err := collect(t, (&ClaudeCode{bin: bin}).Start(t.Context(), 2, "q")); err == nil || !strings.Contains(err.Error(), "Credit balance too low") {
		t.Fatalf("error result: %v", err)
	}
	bin = fakeClaude(t, "echo 'Invalid API key · Please run /login' >&2; exit 1")
	if _, err := collect(t, (&ClaudeCode{bin: bin}).Start(t.Context(), 3, "q")); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("login error: %v", err)
	}
	// Cancelling kills the process.
	bin = fakeClaude(t, "sleep 30")
	ctx, cancel := context.WithCancel(t.Context())
	ch := (&ClaudeCode{bin: bin}).Start(ctx, 4, "q")
	cancel()
	if _, err := collect(t, ch); err == nil || err.Error() != "cancelled" {
		t.Fatalf("cancel: %v", err)
	}
}

func TestPickAsker(t *testing.T) {
	bin := fakeClaude(t, ccOK)
	t.Setenv("PATH", bin[:len(bin)-len("/claude")])
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	a, err := pickAsker("auto", "claude-opus-5-5", false)
	if cc, ok := a.(*ClaudeCode); err != nil || !ok || cc.model != "" {
		t.Fatalf("auto without key: %T %v", a, err)
	}
	a, _ = pickAsker("auto", "claude-sonnet-5-5", true)
	if cc := a.(*ClaudeCode); cc.model != "claude-sonnet-5-5" {
		t.Fatalf("explicit model: %q", cc.model)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	if a, _ = pickAsker("auto", "claude-opus-5-5", false); a.Label() != "claude-opus-5-5 via the API" {
		t.Fatalf("auto with key: %s", a.Label())
	}
	if _, err := pickAsker("bogus", "", false); err == nil {
		t.Fatal("bogus backend accepted")
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "")
	if _, err := pickAsker("auto", "claude-opus-5-5", false); err == nil {
		t.Fatal("auto with nothing available should fail")
	}
}

// Closing the panel mid-answer must not leave the stream goroutine blocked.
func TestStreamGoroutineExitsWhenAbandoned(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	ch := startStream(ctx, 1, func(emit func(string)) error {
		defer close(done)
		for i := 0; i < 200; i++ { // more chunks than the channel buffers
			emit("x")
		}
		return nil
	})
	cancel() // nobody reads ch
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream goroutine blocked after the reader went away")
	}
	for range ch { // the channel still closes
	}
}
