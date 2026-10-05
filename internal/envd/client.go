package envd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxClientFrame bounds one Connect frame sandboxd reads from a guest's envd.
const maxClientFrame = 4 << 20

// RunAsRoot starts command (as "/bin/bash -l -c command") as root through
// sandbox id's envd, authenticated with its access token. With wait unset it
// returns once envd reports the process started; the process keeps running,
// since envd never ties a process to the request that started it. With wait
// set it returns the exit code. Output is discarded. client must reach envd
// (Transport).
func RunAsRoot(ctx context.Context, client *http.Client, id, token, command string, wait bool) (int, error) {
	message, err := json.Marshal(map[string]any{
		"process": map[string]any{"cmd": "/bin/bash", "args": []string{"-l", "-c", command}},
		"stdin":   false,
	})
	if err != nil {
		return 0, err
	}
	body := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message)))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, EnvdURL(id)+"/process.Process/Start", bytes.NewReader(append(body, message...)))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/connect+json")
	request.Header.Set("Connect-Protocol-Version", "1")
	request.Header.Set("X-Access-Token", token)
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("root:")))
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("envd process start answered %d", response.StatusCode)
	}
	started := false
	for {
		var header [5]byte
		if _, err := io.ReadFull(response.Body, header[:]); err != nil {
			return 0, fmt.Errorf("envd process stream ended early: %w", err)
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size > maxClientFrame {
			return 0, errors.New("envd process frame too large")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(response.Body, payload); err != nil {
			return 0, fmt.Errorf("envd process stream ended early: %w", err)
		}
		if header[0]&streamEndFlag != 0 {
			var end struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(payload, &end) == nil && end.Error != nil {
				return 0, fmt.Errorf("envd process failed: %s: %s", end.Error.Code, end.Error.Message)
			}
			return 0, errors.New("envd process stream ended without an exit")
		}
		var event struct {
			Event struct {
				Start *struct{} `json:"start"`
				End   *struct {
					ExitCode int    `json:"exitCode"`
					Exited   bool   `json:"exited"`
					Status   string `json:"status"`
					Error    string `json:"error"`
				} `json:"end"`
			} `json:"event"`
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return 0, fmt.Errorf("malformed envd process event: %w", err)
		}
		switch {
		case event.Event.Start != nil:
			started = true
			if !wait {
				return 0, nil
			}
		case event.Event.End != nil:
			if !started {
				return 0, errors.New("envd process ended before it started")
			}
			if !event.Event.End.Exited {
				return 0, fmt.Errorf("envd process did not exit: %s %s", event.Event.End.Status, event.Event.End.Error)
			}
			return event.Event.End.ExitCode, nil
		}
	}
}
