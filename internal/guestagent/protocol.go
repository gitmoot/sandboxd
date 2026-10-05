// Package guestagent is the wire protocol between sandboxd and the small agent
// that runs as PID 1 inside a Firecracker guest. The host reaches the agent
// only over vsock (Firecracker's host-initiated Unix socket proxy), never over
// the guest network.
//
// A connection carries exactly one request. The host writes one JSON Request
// line; for OpWrite it then writes exactly Request.Size raw bytes. The agent
// answers with frames: one type byte, a big-endian uint32 payload length and
// the payload. OpExec yields FrameStarted, any number of FrameStdout and
// FrameStderr, then FrameResult. OpWrite and OpPing yield only FrameResult.
// Closing the connection before FrameResult cancels the request: the agent
// kills the command's whole process group.
package guestagent

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Port is the guest vsock port the agent listens on.
const Port = 1024

const (
	OpPing  = "ping"
	OpExec  = "exec"
	OpWrite = "write"
)

const (
	FrameStarted byte = 'S'
	FrameStdout  byte = 'O'
	FrameStderr  byte = 'E'
	FrameResult  byte = 'X'
)

const (
	// MaxRequestBytes bounds the JSON request line.
	MaxRequestBytes = 1 << 20
	// MaxFrameBytes bounds one frame payload.
	MaxFrameBytes = 1 << 20
	// MaxWriteBytes bounds one file write (the drivers' copy limit).
	MaxWriteBytes = 512 << 20
)

// Request is the single request line of a connection.
type Request struct {
	Op   string            `json:"op"`
	Args []string          `json:"args,omitempty"`
	Dir  string            `json:"dir,omitempty"`
	Env  map[string]string `json:"env,omitempty"`
	Path string            `json:"path,omitempty"`
	Size int64             `json:"size,omitempty"`
}

// Started acknowledges an accepted command. ID is a positive per-agent
// correlation number, not a guest PID.
type Started struct {
	ID int `json:"id"`
}

// Result ends every request. Error reports an agent-side failure; a command
// that started and exited reports its status in Code with an empty Error.
type Result struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

// WriteRequest sends the request line.
func WriteRequest(w io.Writer, request Request) error {
	line, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(line) >= MaxRequestBytes {
		return errors.New("guest agent request too large")
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// ReadRequest reads the request line without consuming any following bytes
// beyond what the returned reader buffers; callers must keep reading from it.
func ReadRequest(r *bufio.Reader) (Request, error) {
	var line []byte
	for {
		chunk, prefix, err := r.ReadLine()
		if err != nil {
			return Request{}, err
		}
		line = append(line, chunk...)
		if len(line) >= MaxRequestBytes {
			return Request{}, errors.New("guest agent request too large")
		}
		if !prefix {
			break
		}
	}
	var request Request
	if err := json.Unmarshal(line, &request); err != nil {
		return Request{}, fmt.Errorf("malformed guest agent request: %w", err)
	}
	return request, nil
}

// WriteFrame sends one frame.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > MaxFrameBytes {
		return errors.New("guest agent frame too large")
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// WriteJSONFrame sends one frame with a JSON payload.
func WriteJSONFrame(w io.Writer, kind byte, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return WriteFrame(w, kind, payload)
}

// ReadFrame reads one frame. A truncated frame is an error, never a short
// payload.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > MaxFrameBytes {
		return 0, nil, errors.New("guest agent frame too large")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("truncated guest agent frame: %w", errors.Join(err, io.ErrUnexpectedEOF))
	}
	return header[0], payload, nil
}
