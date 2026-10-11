package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	tea "github.com/charmbracelet/bubbletea"
)

const explainSystem = `You explain network traffic captured by "ears", a packet monitor running on the user's own computer. The user is learning networking. They selected one item in the tool and want to know what it is.

Answer in plain text for a terminal: no markdown, no headings, no bold. Use short paragraphs, and a dash list only if it really helps. Aim for 120 to 250 words.

Cover, in this order:
1. What this traffic most likely is, in one or two sentences, naming the program, service or protocol when the data supports it.
2. The networking concepts it shows, explained concretely using the actual values given (ports, flags, TTL, round-trip time, sizes).
3. Whether it looks normal for a home computer, and if anything is worth checking, the exact thing to look at.

Base every claim on the data given. Server names, process names and the organisation behind an address are strong evidence; city-level geolocation is approximate and cloud addresses only show the datacenter. When you are guessing, say so in the same sentence. Never present a guess as fact.`

// Explainer sends a description of selected traffic to Claude and streams the answer.
type Explainer struct {
	client anthropic.Client
	model  string
}

func NewExplainer(model string, opts ...option.RequestOption) *Explainer {
	return &Explainer{client: anthropic.NewClient(opts...), model: model}
}

// aiMsg carries one piece of a streamed explanation to the UI.
type aiMsg struct {
	id   int
	text string
	done bool
	err  error
}

// Start runs the request in the background and returns a channel of chunks,
// closed after a message with done set.
func (e *Explainer) Start(ctx context.Context, id int, question string) <-chan aiMsg {
	ch := make(chan aiMsg, 64)
	go func() {
		defer close(ch)
		err := e.stream(ctx, question, func(s string) {
			select {
			case ch <- aiMsg{id: id, text: s}:
			case <-ctx.Done():
			}
		})
		ch <- aiMsg{id: id, done: true, err: err}
	}()
	return ch
}

func (e *Explainer) stream(ctx context.Context, question string, emit func(string)) error {
	stream := e.client.Beta.Messages.NewStreaming(ctx, anthropic.BetaMessageNewParams{
		Model:        anthropic.Model(e.model),
		MaxTokens:    16000,
		System:       []anthropic.BetaTextBlockParam{{Text: explainSystem}},
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffortMedium},
		// On a safety-classifier refusal, the API reruns the request on a
		// fallback model chosen per refusal category.
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(question)),
		},
	})
	defer stream.Close()
	refused := false
	for stream.Next() {
		switch ev := stream.Current().AsAny().(type) {
		case anthropic.BetaRawContentBlockDeltaEvent:
			if d, ok := ev.Delta.AsAny().(anthropic.BetaTextDelta); ok {
				emit(d.Text)
			}
		case anthropic.BetaRawMessageDeltaEvent:
			if ev.Delta.StopReason == anthropic.BetaStopReasonRefusal {
				refused = true
			}
		}
	}
	if err := stream.Err(); err != nil {
		return explainErr(err)
	}
	if refused {
		emit("\n\n[The model declined to answer this one. Any text above may be incomplete.]")
	}
	return nil
}

// explainErr turns API failures into a message that says what to do.
func explainErr(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 401, 403:
			return fmt.Errorf("the API rejected the credentials (HTTP %d). Set ANTHROPIC_API_KEY to a key from console.anthropic.com", apiErr.StatusCode)
		case 429:
			return fmt.Errorf("rate limited by the API (HTTP 429). Wait a moment and press a again")
		case 400:
			return fmt.Errorf("the API rejected the request: %s", firstLine(apiErr.Error()))
		}
		if apiErr.StatusCode >= 500 {
			return fmt.Errorf("the API had a server error (HTTP %d). Try again shortly", apiErr.StatusCode)
		}
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("cancelled")
	}
	msg := err.Error()
	if strings.Contains(msg, "api key") || strings.Contains(msg, "API key") || strings.Contains(msg, "credentials") {
		return fmt.Errorf("no API credentials found. Set ANTHROPIC_API_KEY to a key from console.anthropic.com (%s)", firstLine(msg))
	}
	return fmt.Errorf("request failed: %s", firstLine(msg))
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// waitAI is a tea.Cmd that delivers the next chunk from the stream.
func waitAI(ch <-chan aiMsg) tea.Cmd {
	return func() tea.Msg {
		m, ok := <-ch
		if !ok {
			return nil
		}
		return m
	}
}
