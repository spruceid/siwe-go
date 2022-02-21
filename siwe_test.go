package siwe

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

const domain = "example.com"
const address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
const uri = "https://example.com"
const version = "1"
const statement = "Example statement for SIWE"

var issuedAt = time.Now().UTC()
var issuedAtStr = issuedAt.Format(time.RFC3339)
var nonce = GenerateNonce()

const chainId = "1"

var expirationTime = time.Now().UTC().Add(48 * time.Hour)
var expirationTimeStr = expirationTime.Format(time.RFC3339)

var notBefore = time.Now().UTC().Add(-24 * time.Hour)
var notBeforeStr = notBefore.Format(time.RFC3339)

const requestId = "some-id"

var resources = []string{"https://example.com/resources/1", "https://example.com/resources/2"}

var options = InitMessageOptions(map[string]interface{}{
	"statement":      statement,
	"issuedAt":       issuedAt,
	"nonce":          nonce,
	"chainId":        chainId,
	"expirationTime": expirationTime,
	"notBefore":      notBefore,
	"requestId":      requestId,
	"resources":      resources,
})

var message = InitMessage(
	domain,
	address,
	uri,
	version,
	*options,
)

func compareMessage(t *testing.T, a, b *Message) {
	assert.Equal(t, a.Domain, b.Domain, "expected %s, found %s", a.Domain, b.Domain)
	assert.Equal(t, a.Address, b.Address, "expected %s, found %s", a.Address, b.Address)
	assert.Equal(t, a.URI, b.URI, "expected %s, found %s", a.URI, b.URI)
	assert.Equal(t, a.Version, b.Version, "expected %s, found %s", a.Version, b.Version)

	assert.Equal(t, a.Statement, b.Statement, "expected %s, found %s", a.Statement, b.Statement)
	assert.Equal(t, a.IssuedAt, b.IssuedAt, "expected %s, found %s", a.IssuedAt, b.IssuedAt)
	assert.Equal(t, a.Nonce, b.Nonce, "expected %s, found %s", a.Nonce, b.Nonce)
	assert.Equal(t, a.ChainID, b.ChainID, "expected %s, found %s", a.ChainID, b.ChainID)
	assert.Equal(t, a.ExpirationTime, b.ExpirationTime, "expected %s, found %s", a.ExpirationTime, b.ExpirationTime)
	assert.Equal(t, a.NotBefore, b.NotBefore, "expected %s, found %s", a.NotBefore, b.NotBefore)
	assert.Equal(t, a.RequestID, b.RequestID, "expected %s, found %s", a.RequestID, b.RequestID)
	assert.Equal(t, a.Resources, b.Resources, "expected %v, found %v", a.Resources, b.Resources)
}

func TestCreate(t *testing.T) {
	assert.Equal(t, message.Domain, domain, "domain should be %s", domain)
	assert.Equal(t, message.Address, address, "address should be %s", address)
	assert.Equal(t, message.URI, uri, "uri should be %s", uri)
	assert.Equal(t, message.Version, version, "version should be %s", version)

	assert.Equal(t, *message.Statement, statement, "statement should be %s", statement)
	assert.Equal(t, *message.IssuedAt, issuedAtStr, "issuedAt should be %s", issuedAtStr)
	assert.Equal(t, *message.Nonce, nonce, "nonce should be %s", nonce)
	assert.Equal(t, *message.ChainID, chainId, "chainId should be %s", chainId)
	assert.Equal(t, *message.ExpirationTime, expirationTimeStr, "expirationTime should be %s", expirationTimeStr)
	assert.Equal(t, *message.NotBefore, notBeforeStr, "notBefore should be %s", notBeforeStr)
	assert.Equal(t, *message.RequestID, requestId, "requestId should be %s", requestId)
	assert.Equal(t, message.Resources, resources, "resources should be %v", resources)
}

func TestCreateRequired(t *testing.T) {
	options := InitMessageOptions(map[string]interface{}{})
	message := InitMessage(domain, address, uri, version, *options)

	assert.Equal(t, message.Domain, domain, "domain should be %s", domain)
	assert.Equal(t, message.Address, address, "address should be %s", address)
	assert.Equal(t, message.URI, uri, "uri should be %s", uri)
	assert.Equal(t, message.Version, version, "version should be %s", version)

	assert.Nil(t, message.Statement, "statement should be nil")
	assert.NotNil(t, message.IssuedAt, "issuedAt should not be nil")
	assert.NotNil(t, message.Nonce, "nonce should be not nil")
	assert.NotNil(t, message.ChainID, "chainId should not be nil")
	assert.Nil(t, message.ExpirationTime, "expirationTime should be nil")
	assert.Nil(t, message.NotBefore, "notBefore should be nil")
	assert.Nil(t, message.RequestID, "requestId should be nil")
	assert.Len(t, message.Resources, 0, "resources should be empty")
}

func TestPrepareParse(t *testing.T) {
	prepare := message.PrepareMessage()
	parse := ParseMessage(prepare)

	compareMessage(t, message, parse)
}

func TestPrepareParseRequired(t *testing.T) {
	options := InitMessageOptions(map[string]interface{}{})
	message := InitMessage(domain, address, uri, version, *options)

	prepare := message.PrepareMessage()
	parse := ParseMessage(prepare)

	compareMessage(t, message, parse)
}

func TestValidateEmpty(t *testing.T) {
	_, err := message.ValidateMessage("")

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidSignature{"Signature cannot be empty"}, err)
	}
}

func createWallet(t *testing.T) (*ecdsa.PrivateKey, string) {
	privateKey, err := crypto.GenerateKey()
	assert.Nil(t, err)

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return privateKey, address
}

func TestValidateNotBefore(t *testing.T) {
	privateKey, address := createWallet(t)

	options := InitMessageOptions(map[string]interface{}{
		"notBefore": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	})
	message := InitMessage(domain, address, uri, version, *options)
	prepare := message.PrepareMessage()

	hash := crypto.Keccak256Hash([]byte(prepare))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)

	assert.Nil(t, err)

	_, err = message.ValidateMessage(hexutil.Encode(signature))

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidMessage{"Message not yet valid"}, err)
	}
}

func TestValidateExpirationTime(t *testing.T) {
	privateKey, address := createWallet(t)

	options := InitMessageOptions(map[string]interface{}{
		"expirationTime": time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
	})
	message := InitMessage(domain, address, uri, version, *options)
	prepare := message.PrepareMessage()

	hash := crypto.Keccak256Hash([]byte(prepare))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)

	assert.Nil(t, err)

	_, err = message.ValidateMessage(hexutil.Encode(signature))

	if assert.Error(t, err) {
		assert.Equal(t, &ExpiredMessage{"Message expired"}, err)
	}
}

func TestValidate(t *testing.T) {
	privateKey, address := createWallet(t)

	message := InitMessage(domain, address, uri, version, *options)
	prepare := message.PrepareMessage()

	sign := signHash([]byte(prepare))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)
	signature[64] += 27

	assert.Nil(t, err)

	result, err := message.ValidateMessage(hexutil.Encode(signature))

	if assert.NoError(t, err) {
		assert.Equal(t, true, result)
	}
}

func TestValidateTampered(t *testing.T) {
	privateKey, address := createWallet(t)
	_, otherAddress := createWallet(t)

	message := InitMessage(domain, address, uri, version, *options)
	prepare := message.PrepareMessage()

	sign := signHash([]byte(prepare))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)
	signature[64] += 27

	assert.Nil(t, err)

	message = InitMessage(domain, otherAddress, uri, version, *options)
	_, err = message.ValidateMessage(hexutil.Encode(signature))

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidSignature{"Signer address must match message address"}, err)
	}
}
