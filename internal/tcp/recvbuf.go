package tcp

import (
	"io"
	"sync"
)

type RecvBuffer struct {
	buf    []byte
	cond   *sync.Cond
	mu     sync.RWMutex
	closed bool
}

func NewRecvBuffer() *RecvBuffer {
	r := &RecvBuffer{
		buf: make([]byte, 0),
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *RecvBuffer) Write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	r.cond.Signal()
}

func (r *RecvBuffer) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Loop to ensure that the condition is satisfied before exiting
	// If statement wouldn't work here because we can guarantee that
	// the condition is satisified when we are signaled
	for len(r.buf) == 0 && !r.closed {
		r.cond.Wait()
	}
	if len(r.buf) == 0 && r.closed {
		return 0, io.EOF
	}
	// The clients buffer can be of any size, we fit as much as we can
	n := copy(p, r.buf)
	// Remove the data that was added to the clients buffer
	r.buf = r.buf[:n]
	return n, nil
}

func (r *RecvBuffer) CloseWrite() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}
