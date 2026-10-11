package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Asker answers one question with a streamed explanation.
type Asker interface {
	Start(ctx context.Context, id int, question string) <-chan aiMsg
	Label() string // shown under each answer
}

func (e *Explainer) Label() string { return e.model + " via the API" }

// ClaudeCode asks through a headless `claude -p` run, so questions count
// against the user's Claude subscription instead of API credits.
type ClaudeCode struct {
	bin   string // path to the claude binary
	model string // empty means Claude Code's own default
}

func (c *ClaudeCode) Label() string {
	if c.model != "" {
		return c.model + " via Claude Code"
	}
	return "Claude Code"
}

// ccLine is the subset of one stream-json output line that ears reads.
type ccLine struct {
	Type  string `json:"type"`
	Event struct {
		Type  string `json:"type"`
		Delta struct {
			Type       string `json:"type"`
			Text       string `json:"text"`
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	} `json:"event"`
	Subtype string `json:"subtype"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
}

func (c *ClaudeCode) Start(ctx context.Context, id int, question string) <-chan aiMsg {
	ch := make(chan aiMsg, 64)
	go func() {
		defer close(ch)
		err := c.run(ctx, question, func(s string) {
			select {
			case ch <- aiMsg{id: id, text: s}:
			case <-ctx.Done():
			}
		})
		ch <- aiMsg{id: id, done: true, err: err}
	}()
	return ch
}

func (c *ClaudeCode) run(ctx context.Context, question string, emit func(string)) error {
	args := []string{"-p",
		"--output-format", "stream-json", "--include-partial-messages", "--verbose",
		"--tools", "", // answer from the given data only; no file or shell access
		"--no-session-persistence", "--strict-mcp-config",
		"--system-prompt", explainSystem,
	}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Dir = os.TempDir() // keep project CLAUDE.md files out of the context
	cmd.Stdin = strings.NewReader(question)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return errors.New("cancelled")
		}
		return fmt.Errorf("could not start %s: %w", c.bin, err)
	}

	streamed, refused := false, false
	var result *ccLine
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		var l ccLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		switch {
		case l.Type == "stream_event" && l.Event.Type == "content_block_delta" && l.Event.Delta.Type == "text_delta":
			emit(l.Event.Delta.Text)
			streamed = true
		case l.Type == "stream_event" && l.Event.Type == "message_delta" && l.Event.Delta.StopReason == "refusal":
			refused = true
		case l.Type == "result":
			r := l
			result = &r
		}
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return errors.New("cancelled")
	}
	if result != nil && result.IsError {
		return fmt.Errorf("Claude Code returned an error: %s", firstLine(firstNonEmpty(result.Result, result.Subtype, stderr.String())))
	}
	if waitErr != nil {
		msg := firstLine(firstNonEmpty(stderr.String(), waitErr.Error()))
		if strings.Contains(strings.ToLower(msg), "login") || strings.Contains(strings.ToLower(msg), "auth") {
			return fmt.Errorf("Claude Code is not logged in. Run claude once and log in, then press a again (%s)", msg)
		}
		return fmt.Errorf("claude exited with an error: %s", msg)
	}
	if !streamed && result != nil && result.Result != "" {
		emit(result.Result) // older CLIs without partial messages
	}
	if refused {
		emit("\n\n[The model declined to answer this one. Any text above may be incomplete.]")
	}
	return nil
}

// pickAsker chooses the backend for -ai. "auto" prefers the API when a key is
// set, and Claude Code otherwise.
func pickAsker(backend, model string, modelSet bool) (Asker, error) {
	apiModel := model
	ccModel := ""
	if modelSet {
		ccModel = model
	}
	switch backend {
	case "api":
		return NewExplainer(apiModel), nil
	case "claude-code":
		bin, err := exec.LookPath("claude")
		if err != nil {
			return nil, errors.New("-ai-backend claude-code: the claude command is not on PATH")
		}
		return &ClaudeCode{bin: bin, model: ccModel}, nil
	case "auto":
		if os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
			return NewExplainer(apiModel), nil
		}
		if bin, err := exec.LookPath("claude"); err == nil {
			return &ClaudeCode{bin: bin, model: ccModel}, nil
		}
		return nil, errors.New("-ai needs either ANTHROPIC_API_KEY set or the claude command installed")
	}
	return nil, fmt.Errorf("unknown -ai-backend %q: use auto, api or claude-code", backend)
}
