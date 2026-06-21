package tcp

import "testing"

func TestBufferWrite(t *testing.T) {
	b := NewRecvBuffer()
	client := make([]byte, 0)
	received := []byte{0xFF, 0xFE}
	b.Write(received)
	i, err := b.Read(client)
	if err != nil {
		t.Fatalf("error occured: %s", err.Error())
	}
	for i := range len(client[:i]) {
		if client[i] != received[i] {
			t.Fatalf("client=%b, want=%b", client[i], received[i])
		}
	}
}

func TestPartialBufferWrite(t *testing.T) {
	b := NewRecvBuffer()
	client := make([]byte, 2)
	received := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB}
	b.Write(received)
	i, err := b.Read(client)
	if err != nil {
		t.Fatalf("error occured: %s", err.Error())
	}
	if i != 2 {
		t.Fatalf("got=%d, want=%d", i, 2)
	}
	// Client only read 2 bytes
	for i := range len(client[:i]) {
		if client[i] != received[i] {
			t.Fatalf("client=%b, want=%b", client[i], received[i])
		}
	}
	// Check whats still in the buffer
	remaining := received[:i]
	for i := range len(b.buf) {
		if b.buf[i] != remaining[i] {
			t.Fatalf("client=%b, want=%b", b.buf[i], remaining[i])
		}
	}
}
