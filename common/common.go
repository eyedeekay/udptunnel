package udpcommon

import (
	"encoding/hex"
)

// Direction is a byte representing a direction
type Direction byte

// OutBound
// InBound
const (
	OutBound Direction = 'T' // Transmit
	InBound  Direction = 'R' // Receive
)

// Logger is an interface to a structured logger
type Logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}

// ICMP is a constant representing an ICMP byte
// TCP is a constant representing a TCP byte
// UDP is a constant representing a UDP byte
const (
	ICMP = 1
	TCP  = 6
	UDP  = 17
)

// MustDecodeHex panics if the hex cannot be decoded
func MustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
