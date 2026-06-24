package tcb

import "sync"

type SendBuffer struct {
	buf   []byte
	start uint32

	mu sync.RWMutex
}

func NewSendBuffer(start uint32) *SendBuffer {
	return &SendBuffer{
		buf:   make([]byte, 0),
		start: start,
	}
}

func (s *SendBuffer) Write(p []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p)
}

func (s *SendBuffer) Acked(ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := ack - s.start
	if len(s.buf) != 0 {
		s.buf = s.buf[i:]
	}
	s.start = ack
}

func (s *SendBuffer) NextChunk(next uint32, window uint16) ([]byte, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sent := next - s.start
	// Tells us whats already been sent
	// If we've sent everything in the buffer thus far, then we can return
	if sent >= uint32(len(s.buf)) {
		return nil, 0
	}
	// If there's a chunk to send then send the size of the min(buffer, window)
	chunk := s.buf[sent:]
	size := min(len(chunk), int(window))
	return chunk[:size], uint16(size)
}
