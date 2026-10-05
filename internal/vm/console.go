package vm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// ConsoleReader is implemented by drivers that keep an envd guest's console
// output: upstream envd's structured logs (envd runs with -verbose) and
// whatever else the guest writes to its console, one entry per line with the
// host time the line arrived. The output is guest-controlled, bounded by
// Console, and discarded with the VM.
type ConsoleReader interface {
	Console(ctx context.Context, id string) ([]ConsoleLine, error)
}

// ConsoleLine is one line of guest console output.
type ConsoleLine struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// ErrNoConsole reports a VM whose console output this driver does not keep:
// a strict guest, a driver without consoles, or a VM adopted after a restart.
var ErrNoConsole = errors.New("VM console output unavailable")

const (
	// ConsoleMaxBytes bounds what a Console keeps: the newest lines whose
	// text plus ConsoleLineOverhead each sums to at most this.
	ConsoleMaxBytes = 1 << 20
	// ConsoleLineOverhead is charged per kept line, so a flood of empty-ish
	// lines is bounded too.
	ConsoleLineOverhead = 64
	// ConsoleMaxLine is the longest line kept; the rest of a longer line is
	// dropped and the kept part ends with ConsoleTruncated.
	ConsoleMaxLine = 16 << 10
	// ConsoleTruncated marks a line cut at ConsoleMaxLine.
	ConsoleTruncated = " [truncated]"
)

// Console is a bounded, concurrency-safe line buffer fed by a guest's console
// stream (an io.Writer). Lines are split on '\n'; carriage returns and other
// control characters except tab are dropped, invalid UTF-8 is replaced, and
// blank lines are not kept. Only the newest lines within ConsoleMaxBytes are
// kept.
type Console struct {
	mu      sync.Mutex
	lines   []ConsoleLine
	size    int
	partial []byte
	// skipping drops the rest of a line already cut at ConsoleMaxLine.
	skipping bool
	now      func() time.Time
}

// NewConsole returns an empty console.
func NewConsole() *Console { return &Console{now: time.Now} }

// Write appends guest output. It never fails, so the guest is never blocked
// or stopped by its own console.
func (c *Console) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := len(p)
	for len(p) > 0 {
		line, rest, complete := cutLine(p)
		p = rest
		if !c.skipping {
			room := ConsoleMaxLine - len(c.partial)
			if len(line) > room {
				c.partial = append(c.partial, line[:room]...)
				c.add(string(c.partial) + ConsoleTruncated)
				c.partial, c.skipping = c.partial[:0], true
			} else {
				c.partial = append(c.partial, line...)
			}
		}
		if complete {
			if !c.skipping {
				c.add(string(c.partial))
			}
			c.partial, c.skipping = c.partial[:0], false
		}
	}
	return written, nil
}

func cutLine(p []byte) (line, rest []byte, complete bool) {
	for i, b := range p {
		if b == '\n' {
			return p[:i], p[i+1:], true
		}
	}
	return p, nil, false
}

// add keeps one finished line, evicting the oldest beyond ConsoleMaxBytes.
// Callers hold c.mu.
func (c *Console) add(raw string) {
	text := sanitizeConsole(raw)
	if strings.TrimSpace(text) == "" {
		return
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.lines = append(c.lines, ConsoleLine{Time: now().UTC(), Text: text})
	c.size += len(text) + ConsoleLineOverhead
	drop := 0
	for c.size > ConsoleMaxBytes {
		c.size -= len(c.lines[drop].Text) + ConsoleLineOverhead
		drop++
	}
	// Evicted lines stay in the backing array until append reallocates it,
	// which copies only the kept ones: memory stays within about twice the
	// bound, and a flood costs amortized constant time per line.
	c.lines = c.lines[drop:]
}

func sanitizeConsole(raw string) string {
	raw = strings.ToValidUTF8(raw, string(utf8.RuneError))
	return strings.Map(func(r rune) rune {
		if r != '\t' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, raw)
}

// Lines returns a copy of the kept lines, oldest first. A trailing line
// without its newline is not included until it is complete.
func (c *Console) Lines() []ConsoleLine {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ConsoleLine(nil), c.lines...)
}
