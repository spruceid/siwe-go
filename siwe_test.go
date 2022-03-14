package siwe

import (
	"crypto/ecdsa"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

const domain = "example.com"
const addressStr = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"

var address = common.HexToAddress(addressStr)

const uri = "https://example.com"
const version = "1"
const statement = "Example statement for SIWE"

var issuedAt = time.Now().UTC().Format(time.RFC3339)
var nonce = GenerateNonce()

const chainId = 1

var expirationTime = time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)

var notBefore = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)

const requestId = "some-id"

var resources = []string{"https://example.com/resources/1", "https://example.com/resources/2"}

var options = map[string]interface{}{
	"statement":      statement,
	"nonce":          nonce,
	"chainId":        chainId,
	"issuedAt":       issuedAt,
	"expirationTime": expirationTime,
	"notBefore":      notBefore,
	"requestId":      requestId,
	"resources":      resources,
}

var message, _ = InitMessage(
	domain,
	addressStr,
	uri,
	version,
	options,
)

func compareMessage(t *testing.T, a, b *Message) {
	assert.Equal(t, a.domain, b.domain, "expected %s, found %s", a.domain, b.domain)
	assert.Equal(t, a.address, b.address, "expected %s, found %s", a.address, b.address)
	assert.Equal(t, a.uri.String(), b.uri.String(), "expected %s, found %s", a.uri, b.uri)
	assert.Equal(t, a.version, b.version, "expected %s, found %s", a.version, b.version)

	assert.Equal(t, a.statement, b.statement, "expected %s, found %s", a.statement, b.statement)
	assert.Equal(t, a.nonce, b.nonce, "expected %s, found %s", a.nonce, b.nonce)
	assert.Equal(t, a.chainID, b.chainID, "expected %s, found %s", a.chainID, b.chainID)

	assert.Equal(t, a.issuedAt, b.issuedAt, "expected %s, found %s", a.issuedAt, b.issuedAt)
	assert.Equal(t, a.expirationTime, b.expirationTime, "expected %s, found %s", a.expirationTime, b.expirationTime)
	assert.Equal(t, a.notBefore, b.notBefore, "expected %s, found %s", a.notBefore, b.notBefore)

	assert.Equal(t, a.requestID, b.requestID, "expected %s, found %s", a.requestID, b.requestID)
	assert.Equal(t, a.resources, b.resources, "expected %v, found %v", a.resources, b.resources)
}

func TestCreate(t *testing.T) {
	assert.Equal(t, message.domain, domain, "domain should be %s", domain)
	assert.Equal(t, message.address, address, "address should be %s", address)
	assert.Equal(t, message.uri.String(), uri, "uri should be %s", uri)
	assert.Equal(t, message.version, version, "version should be %s", version)

	assert.Equal(t, *message.statement, statement, "statement should be %s", statement)
	assert.Equal(t, message.nonce, nonce, "nonce should be %s", nonce)
	assert.Equal(t, message.chainID, chainId, "chainId should be %s", chainId)

	assert.Equal(t, message.issuedAt, issuedAt, "issuedAt should be %v", issuedAt)
	assert.Equal(t, *message.expirationTime, expirationTime, "expirationTime should be %s", expirationTime)
	assert.Equal(t, *message.notBefore, notBefore, "notBefore should be %s", notBefore)

	assert.Equal(t, *message.requestID, requestId, "requestId should be %s", requestId)
	assert.Equal(t, message.resources, resources, "resources should be %v", resources)
}

func TestCreateRequired(t *testing.T) {
	message, err := InitMessage(domain, addressStr, uri, version, map[string]interface{}{})
	assert.Nil(t, err)

	assert.Equal(t, message.domain, domain, "domain should be %s", domain)
	assert.Equal(t, message.address, address, "address should be %s", address)
	assert.Equal(t, message.uri.String(), uri, "uri should be %s", uri)
	assert.Equal(t, message.version, version, "version should be %s", version)

	assert.Nil(t, message.statement, "statement should be nil")
	assert.NotNil(t, message.nonce, "nonce should be not nil")
	assert.NotNil(t, message.chainID, "chainId should not be nil")

	assert.NotNil(t, message.issuedAt, "issuedAt should not be nil")
	assert.Nil(t, message.expirationTime, "expirationTime should be nil")
	assert.Nil(t, message.notBefore, "notBefore should be nil")

	assert.Nil(t, message.requestID, "requestId should be nil")
	assert.Len(t, message.resources, 0, "resources should be empty")
}

func TestPrepareParse(t *testing.T) {
	prepare := message.String()
	parse, err := ParseMessage(prepare)

	assert.Nil(t, err)

	compareMessage(t, message, parse)
}

func TestPrepareParseRequired(t *testing.T) {
	message, err := InitMessage(domain, addressStr, uri, version, map[string]interface{}{})
	assert.Nil(t, err)

	prepare := message.String()
	parse, err := ParseMessage(prepare)

	assert.Nil(t, err)

	compareMessage(t, message, parse)
}

func TestValidateEmpty(t *testing.T) {
	_, err := message.Verify("", nil, nil)

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

	message, err := InitMessage(domain, address, uri, version, map[string]interface{}{
		"notBefore": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	})
	assert.Nil(t, err)
	prepare := message.String()

	hash := crypto.Keccak256Hash([]byte(prepare))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)

	assert.Nil(t, err)

	_, err = message.Verify(hexutil.Encode(signature), nil, nil)

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidMessage{"Message not yet valid"}, err)
	}
}

func TestValidateExpirationTime(t *testing.T) {
	privateKey, address := createWallet(t)

	message, err := InitMessage(domain, address, uri, version, map[string]interface{}{
		"expirationTime": time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
	})
	assert.Nil(t, err)
	prepare := message.String()

	hash := crypto.Keccak256Hash([]byte(prepare))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)

	assert.Nil(t, err)

	_, err = message.Verify(hexutil.Encode(signature), nil, nil)

	if assert.Error(t, err) {
		assert.Equal(t, &ExpiredMessage{"Message expired"}, err)
	}
}

func TestValidate(t *testing.T) {
	privateKey, address := createWallet(t)

	message, err := InitMessage(domain, address, uri, version, options)
	assert.Nil(t, err)

	hash := message.eip191Hash()
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	signature[64] += 27

	assert.Nil(t, err)

	_, err = message.Verify(hexutil.Encode(signature), nil, nil)

	assert.Nil(t, err)
}

func TestValidateTampered(t *testing.T) {
	privateKey, address := createWallet(t)
	_, otherAddress := createWallet(t)

	message, err := InitMessage(domain, address, uri, version, options)
	assert.Nil(t, err)

	hash := message.eip191Hash()
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	signature[64] += 27

	assert.Nil(t, err)

	message, err = InitMessage(domain, otherAddress, uri, version, options)
	assert.Nil(t, err)
	_, err = message.Verify(hexutil.Encode(signature), nil, nil)

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidSignature{"Signer address must match message address"}, err)
	}
}

func assertCase(t *testing.T, fields map[string]interface{}, parsed string, key string) {
	if field, ok := fields[key]; ok {
		assert.Equal(t, field, parsed, "%s should be %s", key, field)
	}
}

func parsingNegative(t *testing.T, cases map[string]interface{}) {
	for name, message := range cases {
		_, err := ParseMessage(message.(string))
		assert.Error(t, err, name)
	}
}

func parsingPositive(t *testing.T, cases map[string]interface{}) {
	for name, v := range cases {
		data := v.(map[string]interface{})
		message := data["message"].(string)
		fields := data["fields"].(map[string]interface{})
		parsed, err := parseMessage(message)
		assert.Nil(t, err, name)

		assertCase(t, fields, parsed["domain"].(string), "domain")
		assertCase(t, fields, parsed["address"].(string), "address")
		assertCase(t, fields, parsed["uri"].(string), "uri")
		assertCase(t, fields, parsed["version"].(string), "version")
		assertCase(t, fields, parsed["chainId"].(string), "chainId")
		assertCase(t, fields, parsed["issuedAt"].(string), "issuedAt")

		if val, ok := parsed["statement"]; ok {
			assertCase(t, fields, val.(string), "statement")
		}

		if val, ok := parsed["nonce"]; ok {
			assertCase(t, fields, val.(string), "nonce")
		}

		constructed, err := ParseMessage(message)
		assert.Nil(t, err)
		assert.Equal(t, constructed.String(), message)
	}
}

func validationNegative(t *testing.T, cases map[string]interface{}) {
	for name, v := range cases {
		data := v.(map[string]interface{})
		message, err := InitMessage(
			data["domain"].(string),
			data["address"].(string),
			data["uri"].(string),
			data["version"].(string),
			data,
		)
		assert.Nil(t, err)

		_, err = message.Verify(data["signature"].(string), nil, nil)

		assert.Error(t, err, name)
	}
}

func validationPositive(t *testing.T, cases map[string]interface{}) {
	for name, v := range cases {
		data := v.(map[string]interface{})
		message, err := InitMessage(
			data["domain"].(string),
			data["address"].(string),
			data["uri"].(string),
			data["version"].(string),
			data,
		)
		assert.Nil(t, err)

		_, err = message.Verify(data["signature"].(string), nil, nil)

		assert.Nil(t, err, name)
	}
}

func TestGlobalTestVector(t *testing.T) {
	files := make(map[string]*os.File, 4)
	for test, filename := range map[string]string{
		"parsing-negative":    "siwe-js/test/parsing_negative.json",
		"parsing-positive":    "siwe-js/test/parsing_positive.json",
		"validation-negative": "siwe-js/test/validation_negative.json",
		"validation-positive": "siwe-js/test/validation_positive.json",
	} {
		file, err := os.Open(filename)
		assert.Nil(t, err)
		files[test] = file
		defer file.Close()
	}

	for test, file := range files {
		data, _ := ioutil.ReadAll(file)

		var result map[string]interface{}
		err := json.Unmarshal([]byte(data), &result)
		assert.Nil(t, err)

		switch test {
		case "parsing-negative":
			parsingNegative(t, result)
		case "parsing-positive":
			parsingPositive(t, result)
		case "validation-negative":
			validationNegative(t, result)
		case "validation-positive":
			validationPositive(t, result)
		}
	}
}
