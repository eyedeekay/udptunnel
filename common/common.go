package udpcommon

type Direction byte

const (
	outbound Direction = 'T' // Transmit
	inbound  Direction = 'R' // Receive
)

type Logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}
