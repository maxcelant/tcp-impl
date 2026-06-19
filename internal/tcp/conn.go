package tcp

import (
	"slices"
	"sync"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
	"github.com/maxcelant/tcp-from-scratch/internal/tcb"
)

type Conn struct {
	TCB *tcb.TCB
	buf []byte

	mu sync.RWMutex
}

func (c *Conn) State() tcb.State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TCB.State
}

func (c *Conn) marshalTCP(dst []byte, flags uint8, payload []byte) ([]byte, error) {
	return (Header{
		SourcePort: c.TCB.Local.Port(),
		DestPort:   c.TCB.Remote.Port(),
		Flags:      flags,
		Window:     c.TCB.Snd.WND,
		SeqNumber:  c.TCB.Snd.NXT,
		AckNumber:  c.TCB.Recv.NXT,
		DataOffset: 5,
	}).AppendMarshal(dst, c.TCB.Local.Addr(), c.TCB.Remote.Addr(), payload)
}

func (c *Conn) marshalIP(dst []byte, payloadSize uint16) ([]byte, error) {
	i, err := (&ipv4.Header{
		Version: 4,
		IHL:     5,
		// 20 bytes for IP header + 20 bytes for TCP header + payload
		// TODO Make dynamic in a clean way
		TotalLength: 40 + payloadSize,
		TTL:         64,
		Protocol:    ipv4.ProtoStrToUInt8[ipv4.ProtoTCP],
		SourceAddr:  c.TCB.Local.Addr(),
		DestAddr:    c.TCB.Remote.Addr(),
		// + Identification, Flags/FragOffset=0, header checksum
	}).Marshal(dst)
	if err != nil {
		return dst[:i], err
	}
	return dst[:i], nil

}

func (c *Conn) send(flags uint8, payload []byte, f func([]byte) error) error {
	buf := make([]byte, 20)
	buf, err := c.marshalIP(buf, uint16(len(payload)))
	if err != nil {
		return err
	}
	buf, err = c.marshalTCP(buf, flags, payload)
	if err != nil {
		return err
	}
	return f(slices.Concat(buf, payload))
}
