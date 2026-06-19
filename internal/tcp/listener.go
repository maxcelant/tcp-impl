package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
	"github.com/maxcelant/tcp-from-scratch/internal/tcb"
	"github.com/maxcelant/tcp-from-scratch/internal/tun"
)

type ctxKey struct{}

var loggerKey = ctxKey{}

type Listener struct {
	local  netip.AddrPort
	demux  *demux
	device *tun.Device
	connCh chan *Conn
	logger *slog.Logger
}

func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

func Listen(ctx context.Context, local netip.AddrPort) (*Listener, error) {
	logger := FromContext(ctx)
	d, err := tun.Open("tun0")
	if err != nil {
		return nil, err
	}

	l := &Listener{
		local:  local,
		demux:  NewDemux(),
		device: d,
		connCh: make(chan *Conn, 100),
		logger: logger,
	}

	buf := make([]byte, 1500)
	go func() {
		for {
			i, err := l.device.Read(buf)
			if err != nil {
				logger.Error("listener: failed to read from device", "name", l.device.Name(), "error", err.Error())
				return
			}
			ip, payload, err := ipv4.Parse(buf[:i])
			if err != nil {
				logger.Error("listener: failed to parse IP packet", "error", err)
				continue
			}
			if !ip.IsProtocol(ipv4.ProtoTCP) {
				logger.Debug("listener: packet protocol is not TCP, skipping")
				continue
			}
			seg, payload, err := Parse(payload[:i])
			if err != nil {
				logger.Error("listener: failed to parse TCP segment", "error", err)
				continue
			}
			connKey := connKey{
				local:  netip.MustParseAddrPort(fmt.Sprintf("%s:%s", ip.DestAddr.String(), strconv.Itoa(int(seg.DestPort)))),
				remote: netip.MustParseAddrPort(fmt.Sprintf("%s:%s", ip.SourceAddr.String(), strconv.Itoa(int(seg.SourcePort)))),
			}
			var conn *Conn
			conn, exists := l.demux.Get(connKey)
			if !exists {
				conn = &Conn{
					TCB: &tcb.TCB{
						State: tcb.StateListen,
						Snd: tcb.Send{
							ISS: 0, // TODO Make this a random number
							UNA: 0,
							WND: 1460,
							NXT: 0,
						},
						Recv: tcb.Receive{
							NXT: seg.SeqNumber + 1,
							WND: seg.Window,
							IRS: seg.SeqNumber,
						},
						Local:  connKey.local,
						Remote: connKey.remote,
					},
				}

			}
			switch conn.State() {
			case tcb.StateListen:
				if connKey.local != l.local {
					continue // not addressed to us; ignore (later: RST)
				}
				if seg.Flags != FlagSYN {
					// TODO Send RST
					logger.Warn("listener: received new connection without SYN flag")
					continue
				}
				if ok := l.demux.Set(connKey, conn); !ok {
					logger.Info("listener: connection already exists in demux map", "connKey", connKey)
				}
				if err := conn.send(FlagSYN|FlagACK, nil, func(b []byte) error {
					_, err := l.device.Write(b)
					return err
				}); err != nil {
					logger.Error("listener: failed to write to device", "error", err)
					continue
				}
				conn.TCB.Snd.NXT = conn.TCB.Snd.ISS + 1
				conn.TCB.State = tcb.StateSynReceived
			case tcb.StateSynReceived:
				// Tells us what it expects its position to be at
				if seg.SeqNumber != conn.TCB.Recv.NXT {
					logger.Error("listener: SEQ does not equal RCV.NXT", "seq", seg.SeqNumber, "rcv.nxt", conn.TCB.Recv.NXT)
					continue
				}
				// Tells us how much of our data it has processed
				if seg.AckNumber != conn.TCB.Snd.NXT {
					logger.Error("listener: ACK does not equal SND.NXT", "ack", seg.AckNumber, "snd.nxt", conn.TCB.Snd.NXT)
					continue
				}
				switch seg.Flags {
				case FlagACK:
					break
				case FlagRST:
					logger.Warn("listener: RST flag set, removing connection")
					l.demux.Delete(connKey)
				default:
					logger.Error("listener: ACK flag not set in segment")
					continue
				}
				conn.TCB.Snd.UNA = seg.AckNumber
				conn.TCB.State = tcb.StateEstablished
				l.connCh <- conn
			}

		}
	}()
	return l, nil
}

func (l *Listener) Accept() (*Conn, error) {
	return <-l.connCh, nil
}

func (l *Listener) Close() error {
	l.logger.Info("listener: closing device")
	return l.device.Close()
}
