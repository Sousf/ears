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

const explainSystem = `You explain network traffic captured by "ears", a packet monitor on the user's own computer. The user selected one item and wants to know what it is.

Be concise: at most 80 words, plain text for a terminal, no markdown. Say what it most likely is, then anything worth checking. Use the actual values given. Skip background explanations unless they are needed to answer.

Base every claim on the data given. When guessing, say so in the same sentence.`

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
	return startStream(ctx, id, func(emit func(string)) error { return e.stream(ctx, question, emit) })
}

// declinedNote ends an answer the model refused partway.
const declinedNote = "\n\n[declined]"

// startStream runs one backend request in the background and delivers its
// text as aiMsg chunks, closing the channel after a final done message.
func startStream(ctx context.Context, id int, run func(emit func(string)) error) <-chan aiMsg {
	ch := make(chan aiMsg, 64)
	go func() {
		defer close(ch)
		send := func(m aiMsg) {
			select {
			case ch <- m: // deliver whenever the buffer has room
				return
			default:
			}
			select {
			case ch <- m:
			case <-ctx.Done(): // buffer full and the panel closed: nobody is reading
			}
		}
		err := run(func(s string) { send(aiMsg{id: id, text: s}) })
		send(aiMsg{id: id, done: true, err: err})
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
		emit(declinedNote)
	}
	return nil
}

// explainErr turns API failures into a message that says what to do.
func explainErr(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 401, 403:
			return fmt.Errorf("API key rejected (HTTP %d): check ANTHROPIC_API_KEY", apiErr.StatusCode)
		case 429:
			return fmt.Errorf("rate limited, try again shortly")
		case 400:
			return fmt.Errorf("request rejected: %s", firstLine(apiErr.Error()))
		}
		if apiErr.StatusCode >= 500 {
			return fmt.Errorf("API server error (HTTP %d)", apiErr.StatusCode)
		}
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("cancelled")
	}
	msg := err.Error()
	if strings.Contains(msg, "api key") || strings.Contains(msg, "API key") || strings.Contains(msg, "credentials") {
		return fmt.Errorf("no API key: set ANTHROPIC_API_KEY")
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
