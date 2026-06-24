package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
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
			ipheader, payload, err := ipv4.Parse(buf[:i])
			if err != nil {
				logger.Error("listener: failed to parse IP packet", "error", err)
				continue
			}
			if !ipheader.IsProtocol(ipv4.ProtoTCP) {
				logger.Debug("listener: packet protocol is not TCP, skipping")
				continue
			}
			tcpheader, payload, err := Parse(payload)
			if err != nil {
				logger.Error("listener: failed to parse TCP segment", "error", err)
				continue
			}
			connKey := connKey{
				local:  netip.MustParseAddrPort(fmt.Sprintf("%s:%s", ipheader.DestAddr.String(), strconv.Itoa(int(tcpheader.DestPort)))),
				remote: netip.MustParseAddrPort(fmt.Sprintf("%s:%s", ipheader.SourceAddr.String(), strconv.Itoa(int(tcpheader.SourcePort)))),
			}
			if connKey.local != l.local {
				logger.Error("listener: connection address does not match listener address", "listenerAddr", l.local)
				continue
			}
			var conn *Conn
			conn, exists := l.demux.Get(connKey)
			if !exists {
				conn = NewConn(ConnOpts{
					logger:   logger,
					device:   d,
					key:      connKey,
					acceptCh: l.connCh,
				})
				if ok := l.demux.Set(connKey, conn); !ok {
					logger.Info("listener: connection already exists in demux map", "connKey", connKey, "state", conn.State().String())
					continue
				}
			}
			conn.segCh <- &Segment{ipheader, tcpheader, payload}
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
