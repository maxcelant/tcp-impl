package tcp

import (
	"context"
	"log/slog"
	"slices"
	"sync"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
	"github.com/maxcelant/tcp-from-scratch/internal/tcb"
	"github.com/maxcelant/tcp-from-scratch/internal/tun"
)

type Segment struct {
	ipheader  *ipv4.Header
	tcpheader *Header
	payload   []byte
}

type Conn struct {
	TCB *tcb.TCB

	ctx      context.Context
	logger   *slog.Logger
	cancel   context.CancelFunc
	device   *tun.Device
	rcvBuf   *tcb.RecvBuffer
	sndBuf   *tcb.SendBuffer
	connKey  connKey
	segCh    chan *Segment
	writeCh  chan struct{}
	acceptCh chan *Conn
	closeCh  chan struct{}
	mu       sync.RWMutex
	closed   bool
}

type ConnOpts struct {
	logger   *slog.Logger
	device   *tun.Device
	key      connKey
	acceptCh chan *Conn
}

func NewConn(opts ConnOpts) *Conn {
	c := &Conn{
		logger:   opts.logger,
		device:   opts.device,
		acceptCh: opts.acceptCh,
		rcvBuf:   tcb.NewRecvBuffer(),
		sndBuf:   tcb.NewSendBuffer(1), // TODO Use ISS
		segCh:    make(chan *Segment, 100),
		writeCh:  make(chan struct{}, 1),
		closeCh:  make(chan struct{}, 1),
		TCB: &tcb.TCB{
			State:  tcb.StateListen,
			Local:  opts.key.local,
			Remote: opts.key.remote,
		},
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	go c.loop()
	return c

}

func (c *Conn) Read(p []byte) (int, error) {
	return c.rcvBuf.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	n := c.sndBuf.Write(p)
	select {
	case c.writeCh <- struct{}{}: // non-blocking wake
	default:
	}
	return n, nil
}

func (c *Conn) Close() {
	c.cancel()
}

func (c *Conn) State() tcb.State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TCB.State
}

func (c *Conn) loop() {
	for {
		select {
		case seg := <-c.segCh: // from the demux goroutine
			c.handleSegment(seg) // the state-machine switch lives here now
			if c.State() == tcb.StateEstablished {
				c.send() // ack / push data / window updates
			}

		case <-c.writeCh: // Conn.Write signalled "new bytes buffered"
			c.send()

			// TODO implement in next lesson
			// case <-c.rtxTimer.C: // retransmit timer (L11)
			// 	c.TCB.Snd.NXT = c.TCB.Snd.UNA
			// 	c.output()

			// case <-c.ctx.Done(): // app called Close() (L13)
			// 	c.sendFin()
			// }
		}
	}
}

func (c *Conn) handleSegment(seg *Segment) {
	switch c.State() {
	case tcb.StateListen:
		// Create the TCB state
		c.TCB.Snd = tcb.Send{
			ISS: 0, // TODO Make this a random number
			UNA: 0,
			WND: 1460,
			NXT: 0,
		}
		c.TCB.Recv = tcb.Receive{
			NXT: seg.tcpheader.SeqNumber + 1,
			WND: seg.tcpheader.Window,
			IRS: seg.tcpheader.SeqNumber,
		}
		if seg.tcpheader.Flags != FlagSYN {
			// TODO Send RST
			c.logger.Warn("conn: received new connection without SYN flag")
			return
		}
		c.sendCtl(FlagSYN | FlagACK)
		c.TCB.Snd.NXT = c.TCB.Snd.ISS + 1
		c.TCB.State = tcb.StateSynReceived
	case tcb.StateSynReceived:
		// Tells us what the remote expects its position to be at
		// If it isn't correct, then we must have some out of order issue, we will handle this later
		if seg.tcpheader.SeqNumber != c.TCB.Recv.NXT {
			c.logger.Warn("conn: SEQ does not equal RCV.NXT", "seq", seg.tcpheader.SeqNumber, "rcv.nxt", c.TCB.Recv.NXT, "state", c.State().String())
			return
		}
		// Tells us how much of our data the remote has processed
		if seg.tcpheader.AckNumber != c.TCB.Snd.NXT {
			c.logger.Error("conn: ACK does not equal SND.NXT", "ack", seg.tcpheader.AckNumber, "snd.nxt", c.TCB.Snd.NXT, "state", c.State().String())
			return
		}
		switch seg.tcpheader.Flags {
		case FlagACK:
			break

		// TODO Handle this
		// case FlagRST:
		// 	c.logger.Warn("conn: RST flag set, removing connection")
		// 	l.demux.Delete(connKey)
		default:
			c.logger.Error("conn: ACK flag not set in segment")
			return
		}
		c.TCB.Snd.UNA = seg.tcpheader.AckNumber
		c.TCB.State = tcb.StateEstablished
		// TODO Figure out how to handle this part
		c.acceptCh <- c
	case tcb.StateEstablished:
		if seg.tcpheader.SeqNumber < c.TCB.Recv.NXT {
			c.logger.Warn("conn: SEQ does not equal RCV.NXT", "seq", seg.tcpheader.SeqNumber, "rcv.nxt", c.TCB.Recv.NXT, "state", c.State().String())
			return
		}
		// We have some payload to send to the remote
		if c.TCB.Snd.UNA < seg.tcpheader.AckNumber && seg.tcpheader.AckNumber <= c.TCB.Snd.NXT {
			c.TCB.Snd.UNA = seg.tcpheader.AckNumber
			c.sndBuf.Acked(seg.tcpheader.AckNumber)
			c.TCB.Snd.WND = seg.tcpheader.Window
			c.logger.Debug("sending data to remote", "SND.NXT", c.TCB.Snd.NXT, "state", c.State().String())
		}
		// Got some payload, and we need to send it to the connection buffer
		if len(seg.payload) > 0 {
			c.rcvBuf.Write(seg.payload)
			c.TCB.Recv.NXT += uint32(len(seg.payload))
			c.logger.Debug("retrieving data from remote", "RCV.NXT", c.TCB.Recv.NXT, "state", c.State().String())
		}
	}
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

func (c *Conn) sendCtl(flags uint8) error {
	buf := make([]byte, 20)
	buf, err := c.marshalIP(buf, 0)
	if err != nil {
		return err
	}
	buf, err = c.marshalTCP(buf, flags, nil)
	if err != nil {
		return err
	}
	_, err = c.device.Write(slices.Concat(buf, nil))
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) send() error {
	if c.TCB.State != tcb.StateEstablished {
		return nil
	}
	payload, i := c.sndBuf.NextChunk(c.TCB.Snd.NXT, c.TCB.Snd.WND)
	buf := make([]byte, 20)
	buf, err := c.marshalIP(buf, i)
	if err != nil {
		return err
	}
	buf, err = c.marshalTCP(buf, FlagACK, payload)
	if err != nil {
		return err
	}
	_, err = c.device.Write(slices.Concat(buf, payload))
	if err != nil {
		return err
	}
	c.TCB.Snd.NXT += uint32(i)
	return nil
}
