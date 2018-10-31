package udpcommon

type direction byte

const (
	outbound direction = 'T' // Transmit
	inbound  direction = 'R' // Receive
)

type logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}
