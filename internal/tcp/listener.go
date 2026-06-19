package tcp

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"

	"github.com/maxcelant/tcp-from-scratch/internal/ipv4"
	"github.com/maxcelant/tcp-from-scratch/internal/tcb"
	"github.com/maxcelant/tcp-from-scratch/internal/tun"
)

type Listener struct {
	local  netip.AddrPort
	demux  *demux
	device *tun.Device
	connCh chan *Conn
}

func Listen(local netip.AddrPort) (*Listener, error) {
	d, err := tun.Open("tun0")
	if err != nil {
		return nil, err
	}

	l := &Listener{
		local:  local,
		demux:  NewDemux(),
		device: d,
		connCh: make(chan *Conn, 100),
	}

	buf := make([]byte, 1500)
	go func() {
		for {
			i, err := l.device.Read(buf)
			if err != nil {
				log.Printf("listener(error): failed to read for device: %s: %s\n", l.device.Name(), err.Error())
				return
			}
			ip, payload, err := ipv4.Parse(buf[:i])
			if err != nil {
				log.Printf("listener(error): error occured while parsing buffer: %s\n", err.Error())
				continue
			}
			if !ip.IsProtocol(ipv4.ProtoTCP) {
				log.Println("listener(error): protocol for packet is not TCP, skipping")
				continue
			}
			seg, payload, err := Parse(payload[:i])
			if err != nil {
				log.Printf("listener(error): failure occured while parsing buffer: %s\n", err.Error())
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
					log.Println("listener(warning): received new connection without SYN flag")
					continue
				}
				if ok := l.demux.Set(connKey, conn); !ok {
					log.Printf("listener(info): connection already exists in demux map :%v\n", connKey)
				}
				if err := conn.send(FlagSYN|FlagACK, nil, func(b []byte) error {
					_, err := l.device.Write(b)
					return err
				}); err != nil {
					log.Printf("listener(error): failed during write to device: %s", err.Error())
					continue
				}
				conn.TCB.Snd.NXT = conn.TCB.Snd.ISS + 1
				conn.TCB.State = tcb.StateSynReceived
			case tcb.StateSynReceived:
				// Tells us what it expects its position to be at
				if seg.SeqNumber != conn.TCB.Recv.NXT {
					log.Printf("listener(error): SEQ does not equal RCV.NXT %d!=%d\n", seg.SeqNumber, conn.TCB.Recv.NXT)
					continue
				}
				// Tells us how much of our data it has processed
				if seg.AckNumber != conn.TCB.Snd.NXT {
					log.Printf("listener(error): ACK does not equal SND.NXT %d!=%d\n", seg.AckNumber, conn.TCB.Snd.NXT)
					continue
				}
				switch seg.Flags {
				case FlagACK:
					break
				case FlagRST:
					log.Println("listener(warning): RST flag set, removing connection")
					l.demux.Delete(connKey)
				default:
					log.Println("listener(error): ACK flag not set in segment")
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
	log.Println("listener: closing device")
	return l.device.Close()
}
