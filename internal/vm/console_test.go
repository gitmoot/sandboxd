package vm

import (
	"strings"
	"testing"
	"time"
)

func TestConsoleSplitsSanitizesAndStamps(t *testing.T) {
	c := NewConsole()
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.FixedZone("x", 3600))
	c.now = func() time.Time { return at }
	for _, chunk := range []string{"fir", "st\r\n\n  \nsec\x1b[1mond\t", "x\xffy\nthird without newline"} {
		if n, err := c.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	lines := c.Lines()
	want := []string{"first", "sec[1mond\tx\uFFFDy"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %+v", lines)
	}
	for i, line := range lines {
		if line.Text != want[i] || !line.Time.Equal(at) || line.Time.Location() != time.UTC {
			t.Fatalf("line %d = %+v, want %q at %v UTC", i, line, want[i], at)
		}
	}
	// Lines is a copy.
	lines[0].Text = "changed"
	if c.Lines()[0].Text != "first" {
		t.Fatal("Lines shares its slice")
	}
}

func TestConsoleTruncatesLongLines(t *testing.T) {
	c := NewConsole()
	long := strings.Repeat("a", ConsoleMaxLine+100)
	// Written in pieces, so the cut can fall inside a partial line.
	_, _ = c.Write([]byte(long[:ConsoleMaxLine-10]))
	_, _ = c.Write([]byte(long[ConsoleMaxLine-10:] + "\nnext\n"))
	lines := c.Lines()
	if len(lines) != 2 || lines[0].Text != strings.Repeat("a", ConsoleMaxLine)+ConsoleTruncated || lines[1].Text != "next" {
		t.Fatalf("got %d lines, first %d bytes, second %q", len(lines), len(lines[0].Text), lines[len(lines)-1].Text)
	}
}

func TestConsoleKeepsOnlyTheNewestWithinItsBound(t *testing.T) {
	c := NewConsole()
	line := strings.Repeat("b", 1000) + "\n"
	total := 3 * ConsoleMaxBytes / (len(line) - 1 + ConsoleLineOverhead)
	for range total {
		_, _ = c.Write([]byte(line))
	}
	_, _ = c.Write([]byte("last\n"))
	lines := c.Lines()
	size := 0
	for _, l := range lines {
		size += len(l.Text) + ConsoleLineOverhead
	}
	if size > ConsoleMaxBytes || size < ConsoleMaxBytes-1100 || lines[len(lines)-1].Text != "last" {
		t.Fatalf("kept %d lines, %d bytes", len(lines), size)
	}
}
