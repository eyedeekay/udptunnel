package udpcommon

import (
	"encoding/hex"
)

type Direction byte

const (
	OutBound Direction = 'T' // Transmit
	InBound  Direction = 'R' // Receive
)

type Logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}

const (
	ICMP = 1
	TCP  = 6
	UDP  = 17
)

func MustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
