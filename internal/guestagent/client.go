package guestagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Handshake performs Firecracker's host-initiated vsock handshake on a fresh
// connection to the VM's vsock Unix socket. It reads byte by byte so no
// agent data is consumed.
func Handshake(conn io.ReadWriter, port int) error {
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		return err
	}
	var line []byte
	var one [1]byte
	for len(line) < 64 {
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return fmt.Errorf("vsock handshake: %w", err)
		}
		if one[0] == '\n' {
			fields := strings.Fields(string(line))
			if len(fields) != 2 || fields[0] != "OK" {
				return fmt.Errorf("vsock handshake refused: %q", string(line))
			}
			if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
				return fmt.Errorf("vsock handshake refused: %q", string(line))
			}
			return nil
		}
		line = append(line, one[0])
	}
	return errors.New("vsock handshake reply too long")
}

// closeOnCancel closes conn when ctx ends; the returned stop must be called.
func closeOnCancel(ctx context.Context, conn io.Closer) func() bool {
	return context.AfterFunc(ctx, func() { _ = conn.Close() })
}

func readResult(conn io.Reader) (Result, error) {
	kind, payload, err := ReadFrame(conn)
	if err != nil {
		return Result{}, err
	}
	if kind != FrameResult {
		return Result{}, fmt.Errorf("unexpected guest agent frame %q", kind)
	}
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, fmt.Errorf("malformed guest agent result: %w", err)
	}
	return result, nil
}

// Ping confirms the agent is serving.
func Ping(ctx context.Context, conn io.ReadWriteCloser) error {
	defer closeOnCancel(ctx, conn)()
	if err := WriteRequest(conn, Request{Op: OpPing}); err != nil {
		return contextErr(ctx, err)
	}
	result, err := readResult(conn)
	if err != nil {
		return contextErr(ctx, err)
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

func contextErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Exec runs a command and streams its output. onStart receives the agent's
// positive correlation ID once the request is accepted. A transport failure
// or a truncated stream is an error, never an exit status.
func Exec(ctx context.Context, conn io.ReadWriteCloser, request Request, stdout, stderr io.Writer, onStart func(int)) (int, error) {
	defer closeOnCancel(ctx, conn)()
	request.Op = OpExec
	if err := WriteRequest(conn, request); err != nil {
		return 0, contextErr(ctx, err)
	}
	started := false
	for {
		kind, payload, err := ReadFrame(conn)
		if err != nil {
			return 0, contextErr(ctx, err)
		}
		switch kind {
		case FrameStarted:
			var ack Started
			if started || json.Unmarshal(payload, &ack) != nil || ack.ID <= 0 {
				return 0, errors.New("malformed guest agent start frame")
			}
			started = true
			if onStart != nil {
				onStart(ack.ID)
			}
		case FrameStdout, FrameStderr:
			if !started {
				return 0, errors.New("guest output before start")
			}
			w := stdout
			if kind == FrameStderr {
				w = stderr
			}
			if _, err := w.Write(payload); err != nil {
				return 0, err
			}
		case FrameResult:
			var result Result
			if err := json.Unmarshal(payload, &result); err != nil {
				return 0, fmt.Errorf("malformed guest agent result: %w", err)
			}
			if result.Error != "" {
				return 0, errors.New(result.Error)
			}
			if !started {
				return 0, errors.New("guest command result without start")
			}
			return result.Code, nil
		default:
			return 0, fmt.Errorf("unexpected guest agent frame %q", kind)
		}
	}
}

// Write streams exactly size bytes from r to path in the guest. The agent
// may reject the request before reading the body, so the result is read
// while the body is still being sent; r is no longer read once Write returns.
func Write(ctx context.Context, conn io.ReadWriteCloser, path string, size int64, r io.Reader) error {
	defer closeOnCancel(ctx, conn)()
	if err := WriteRequest(conn, Request{Op: OpWrite, Path: path, Size: size}); err != nil {
		return contextErr(ctx, err)
	}
	copied := make(chan error, 1)
	go func() {
		_, err := io.CopyN(conn, r, size)
		copied <- err
	}()
	result, err := readResult(conn)
	if err != nil || result.Error != "" {
		// Unblock and wait for the sender before giving r back.
		_ = conn.Close()
		<-copied
		if err != nil {
			return contextErr(ctx, err)
		}
		return errors.New(result.Error)
	}
	if err := <-copied; err != nil {
		return contextErr(ctx, err)
	}
	return nil
}
