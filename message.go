package siwe

import (
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/relvacode/iso8601"
)

type Message struct {
	domain  string
	address common.Address
	uri     url.URL
	version string

	statement *string
	nonce     string
	chainID   int

	issuedAt       string
	expirationTime *string
	notBefore      *string

	requestID *string
	resources []url.URL
}

func (m *Message) GetDomain() string {
	return m.domain
}

func (m *Message) GetAddress() common.Address {
	return m.address
}

func (m *Message) GetURI() url.URL {
	return m.uri
}

func (m *Message) GetVersion() string {
	return m.version
}

func (m *Message) GetStatement() *string {
	if m.statement != nil {
		ret := *m.statement
		return &ret
	}
	return nil
}

func (m *Message) GetNonce() string {
	return m.nonce
}

func (m *Message) GetChainID() int {
	return m.chainID
}

func (m *Message) GetIssuedAt() string {
	return m.issuedAt
}

func (m *Message) getExpirationTime() *time.Time {
	if !isEmpty(m.expirationTime) {
		ret, _ := iso8601.ParseString(*m.expirationTime)
		return &ret
	}
	return nil
}

func (m *Message) GetExpirationTime() *string {
	if m.expirationTime != nil {
		ret := *m.expirationTime
		return &ret
	}
	return nil
}

func (m *Message) getNotBefore() *time.Time {
	if !isEmpty(m.notBefore) {
		ret, _ := iso8601.ParseString(*m.notBefore)
		return &ret
	}
	return nil
}

func (m *Message) GetNotBefore() *string {
	if m.notBefore != nil {
		ret := *m.notBefore
		return &ret
	}
	return nil
}

func (m *Message) GetRequestID() *string {
	if m.requestID != nil {
		ret := *m.requestID
		return &ret
	}
	return nil
}

func (m *Message) GetResources() []url.URL {
	return m.resources
}
