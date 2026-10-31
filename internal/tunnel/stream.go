// Package tunnel carries directional EOF across transports that cannot half-close.
package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxData = 32 << 10

// Conn frames data and write-side EOF. Closing the underlying transport without
// an EOF frame is an error, not a directional EOF. Buffers are bounded.
type Conn struct {
	io.ReadWriteCloser
	reader            io.Reader
	readMu, writeMu   sync.Mutex
	left              uint32
	readEOF, writeEOF bool
}

func New(conn io.ReadWriteCloser, reader io.Reader) *Conn {
	if reader == nil {
		reader = conn
	}
	return &Conn{ReadWriteCloser: conn, reader: reader}
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readEOF {
		return 0, io.EOF
	}
	if c.left == 0 {
		var h [5]byte
		if _, err := io.ReadFull(c.reader, h[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		size := binary.BigEndian.Uint32(h[1:])
		if h[0] == 1 && size == 0 {
			c.readEOF = true
			return 0, io.EOF
		}
		if h[0] != 0 || size == 0 || size > maxData {
			return 0, errors.New("invalid tunnel frame")
		}
		c.left = size
	}
	n, err := c.reader.Read(p[:min(len(p), int(c.left))])
	c.left -= uint32(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxData)
		var h [5]byte
		binary.BigEndian.PutUint32(h[1:], uint32(n))
		if err := writeAll(c.ReadWriteCloser, h[:]); err != nil {
			return written, err
		}
		if err := writeAll(c.ReadWriteCloser, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return nil
	}
	c.writeEOF = true
	return writeAll(c.ReadWriteCloser, []byte{1, 0, 0, 0, 0})
}

func (c *Conn) LocalAddr() net.Addr {
	if n, ok := c.ReadWriteCloser.(net.Conn); ok {
		return n.LocalAddr()
	}
	return addr{}
}
func (c *Conn) RemoteAddr() net.Addr {
	if n, ok := c.ReadWriteCloser.(net.Conn); ok {
		return n.RemoteAddr()
	}
	return addr{}
}
func (c *Conn) SetDeadline(t time.Time) error {
	if n, ok := c.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return n.SetDeadline(t)
	}
	return errors.New("tunnel has no deadlines")
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	if n, ok := c.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return n.SetReadDeadline(t)
	}
	return errors.New("tunnel has no deadlines")
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if n, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return n.SetWriteDeadline(t)
	}
	return errors.New("tunnel has no deadlines")
}

type addr struct{}

func (addr) Network() string { return "sandboxd-tunnel" }
func (addr) String() string  { return "sandboxd-tunnel" }

// Bridge propagates EOF independently in each direction. Errors, cancellation
// (by closing either connection), or both EOFs close both connections.
func Bridge(client net.Conn, in io.Reader, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	_, aok := client.(interface{ CloseWrite() error })
	_, bok := upstream.(interface{ CloseWrite() error })
	if !aok || !bok {
		return
	}
	// Each copy reports directional EOF, then keeps observing a framed source
	// for transport cancellation. No data is legal after its EOF frame.
	done := make(chan error, 4)
	var copies sync.WaitGroup
	copies.Add(2)
	copyDirection := func(dst net.Conn, src io.Reader) {
		defer copies.Done()
		_, err := io.Copy(dst, src)
		if err == nil {
			err = dst.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- err
		if err != nil {
			return
		}
		if framed, ok := src.(*Conn); ok {
			framed.readMu.Lock()
			var extra [1]byte
			_, err = io.ReadFull(framed.reader, extra[:])
			framed.readMu.Unlock()
			if err == nil {
				err = errors.New("data after tunnel EOF")
			}
			done <- err
		}
	}
	go copyDirection(upstream, in)
	go copyDirection(client, upstream)
	for completed := 0; completed < 2; completed++ {
		if err := <-done; err != nil {
			break
		}
	}
	_ = client.Close()
	_ = upstream.Close()
	copies.Wait()
}
