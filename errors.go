package siwe

import (
	"fmt"
)

type ExpiredMessage struct{ string }
type InvalidMessage struct{ string }
type InvalidSignature struct{ string }

func (m *ExpiredMessage) Error() string {
	return fmt.Sprintf("Expired Message: %s", m.string)
}

func (m *InvalidMessage) Error() string {
	return fmt.Sprintf("Invalid Message: %s", m.string)
}

func (m *InvalidSignature) Error() string {
	return fmt.Sprintf("Invalid Signature: %s", m.string)
}
