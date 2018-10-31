package udpcommon

type Direction byte

const (
	OutBound Direction = 'T' // Transmit
	InBound  Direction = 'R' // Receive
)

type Logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}
