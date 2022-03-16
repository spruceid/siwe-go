package siwe

import (
	"fmt"
)

type ExpiredMessage struct{ string }
type InvalidMessage struct{ string }
type InvalidSignature struct{ string }

func (m *ExpiredMessage) Error() string {
	return "Expired Message"
}

func (m *InvalidMessage) Error() string {
	return "Invalid Message"
}

func (m *InvalidSignature) Error() string {
	return fmt.Sprintf("Invalid Signature: %s", m.string)
}
