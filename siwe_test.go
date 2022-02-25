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
	parse, err := ParseMessage(prepare)

	assert.Nil(t, err)

	compareMessage(t, message, parse)
}

func TestPrepareParseRequired(t *testing.T) {
	options := InitMessageOptions(map[string]interface{}{})
	message := InitMessage(domain, address, uri, version, *options)

	prepare := message.PrepareMessage()
	parse, err := ParseMessage(prepare)

	assert.Nil(t, err)

	compareMessage(t, message, parse)
}

func TestValidateEmpty(t *testing.T) {
	_, err := message.Verify("")

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

	_, err = message.Verify(hexutil.Encode(signature))

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

	_, err = message.Verify(hexutil.Encode(signature))

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

	_, err = message.Verify(hexutil.Encode(signature))

	assert.Nil(t, err)
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
	_, err = message.Verify(hexutil.Encode(signature))

	if assert.Error(t, err) {
		assert.Equal(t, &InvalidSignature{"Signer address must match message address"}, err)
	}
}

func TestGlobalParsingNegative(t *testing.T) {
	cases := map[string]string{
		"missing mandatory field": "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nVersion: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24Z",
		"extra line breaks":       "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24Z",
		"non-ISO datetime":        "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nNonce: 32891757\nIssued At: Wed Oct 05 2011 16:48:00 GMT+0200 (CEST)",
		"out of order fields":     "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nVersion: 1\nNonce: 32891757\nURI: https://service.org/login\nIssued At: 2021-09-30T16:25:24.000Z",
		"wrong version":           "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 2\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
	}

	for k, v := range cases {
		_, err := ParseMessage(v)
		assert.Error(t, err, k)
	}
}

func TestGlobalParsingPositive(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"couple of optional fields": {
			"message": "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z\nResources:\n- ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu\n- https://example.com/my-web2-claim.json",
			"fields": map[string]interface{}{
				"domain":    "service.org",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
				"resources": []string{"ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu", "https://example.com/my-web2-claim.json"},
			},
		},
		"no optional field": {
			"message": "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":    "service.org",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
			},
		},
		"timestamp without microseconds": {
			"message": "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24Z",
			"fields": map[string]interface{}{
				"domain":    "service.org",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24Z",
			},
		},
		"domain is RFC 3986 authority with IP": {
			"message": "127.0.0.1 wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":    "127.0.0.1",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
			},
		},
		"domain is RFC 3986 authority with userinfo": {
			"message": "test@127.0.0.1 wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":    "test@127.0.0.1",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
			},
		},
		"domain is RFC 3986 authority with port": {
			"message": "127.0.0.1:8080 wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":    "127.0.0.1:8080",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
			},
		},
		"domain is RFC 3986 authority with userinfo and port": {
			"message": "test@127.0.0.1:8080 wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\nI accept the ServiceOrg Terms of Service: https://service.org/tos\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":    "test@127.0.0.1:8080",
				"address":   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
				"uri":       "https://service.org/login",
				"version":   "1",
				"chainId":   "1",
				"nonce":     "32891757",
				"issuedAt":  "2021-09-30T16:25:24.000Z",
			},
		},
		"no statement": {
			"message": "service.org wants you to sign in with your Ethereum account:\n0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\n\n\nURI: https://service.org/login\nVersion: 1\nChain ID: 1\nNonce: 32891757\nIssued At: 2021-09-30T16:25:24.000Z",
			"fields": map[string]interface{}{
				"domain":   "service.org",
				"address":  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
				"uri":      "https://service.org/login",
				"version":  "1",
				"chainId":  "1",
				"nonce":    "32891757",
				"issuedAt": "2021-09-30T16:25:24.000Z",
			},
		},
	}

	for k, v := range cases {
		message := v["message"].(string)
		fields := v["fields"].(map[string]interface{})
		parsed, err := ParseMessage(message)
		assert.Nil(t, err, k)

		validateGlobalCase(t, fields, parsed.Domain, "domain")
		validateGlobalCase(t, fields, parsed.Address, "address")
		validateGlobalCase(t, fields, parsed.URI, "uri")
		validateGlobalCase(t, fields, parsed.Version, "version")

		if parsed.Statement != nil {
			validateGlobalCase(t, fields, *parsed.Statement, "statement")
		}

		if parsed.ChainID != nil {
			validateGlobalCase(t, fields, *parsed.ChainID, "chainId")
		}

		if parsed.Nonce != nil {
			validateGlobalCase(t, fields, *parsed.Nonce, "nonce")
		}

		if parsed.IssuedAt != nil {
			validateGlobalCase(t, fields, *parsed.IssuedAt, "issuedAt")
		}
	}
}

func validateGlobalCase(t *testing.T, fields map[string]interface{}, parsed string, key string) {
	if field, ok := fields[key]; ok {
		assert.Equal(t, parsed, field, "%s should be %s", key, field)
	}
}

func TestValidateNegative(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"expired message": {
			"domain":         "login.xyz",
			"address":        "0x6Da01670d8fc844e736095918bbE11fE8D564163",
			"statement":      "Sign-In With Ethereum Example Statement",
			"uri":            "https://login.xyz",
			"version":        "1",
			"nonce":          "lx2nx4so",
			"issuedAt":       "2022-01-05T14:27:30.883Z",
			"chainId":        "1",
			"expirationTime": "2021-01-05T00:00:00Z",
			"signature":      "0x5e6834e82ec12532e3954882610b26ef83c16d25a38caccc6a009a488b6ad1237318ec6cd2fd83c19f49d0cb0848c70e9a5a4bf550ce5d69bc1b023b9f6b7f601b",
		},
		"malformed signature": {
			"domain":         "login.xyz",
			"address":        "0x6Da01670d8fc844e736095918bbE11fE8D564163",
			"statement":      "Sign-In With Ethereum Example Statement",
			"uri":            "https://login.xyz",
			"version":        "1",
			"nonce":          "rmplqh1gf",
			"issuedAt":       "2022-01-05T14:31:43.954Z",
			"chainId":        "1",
			"expirationTime": "2022-01-07T14:31:43.952Z",
			"signature":      "0xf2e8420fc1b722bf4941f5a0464f98172a758ceda5039f622e425fb69fd19b20e444bba7c9a8a8d7e2b5e453553efe7c9460be5d211abe473fc146d51bb04d0cb1b",
		},
		"wrong signature": {
			"domain":         "login.xyz",
			"address":        "0x6Da01670d8fc844e736095918bbE11fE8D564163",
			"statement":      "Sign-In With Ethereum Example Statement",
			"uri":            "https://login.xyz",
			"version":        "1",
			"nonce":          "rmplqh1gf",
			"issuedAt":       "2022-01-05T14:31:43.954Z",
			"chainId":        "1",
			"expirationTime": "2022-01-07T14:31:43.952Z",
			"signature":      "0x31df81dc02344c9156e6f71da46e2db624b38f8f806290d670d46492b834b2e7575cbce9f48169356cfb577b910d8e30732fcf23c1ac0021d08b945ed7ee118e1b",
		},
		"invalid expiration time": {
			"domain":         "login.xyz",
			"address":        "0x6Da01670d8fc844e736095918bbE11fE8D564163",
			"statement":      "Sign-In With Ethereum Example Statement",
			"uri":            "https://login.xyz",
			"version":        "1",
			"nonce":          "o8zxjgmp",
			"issuedAt":       "2022-01-05T14:50:55.688Z",
			"chainId":        "1",
			"expirationTime": "2020-02-32T00:00:00.000Z",
			"signature":      "0x8b457a36dad94cb9c07cfcad08664c988d795b35762f1316438b9590c27f4a5e028e923066a49908c88a1e2fba299c1e6d6d8206181339343e0ef53be01d078f1c",
		},
	}

	for k, v := range cases {
		message := InitMessage(
			v["domain"].(string),
			v["address"].(string),
			v["uri"].(string),
			v["version"].(string),
			*InitMessageOptions(v),
		)

		_, err := message.Verify(v["signature"].(string))

		assert.Error(t, err, k)
	}
}

func TextValidatePositive(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"example message": {
			"domain":         "login.xyz",
			"address":        "0x9D85ca56217D2bb651b00f15e694EB7E713637D4",
			"statement":      "Sign-In With Ethereum Example Statement",
			"uri":            "https://login.xyz",
			"version":        "1",
			"nonce":          "bTyXgcQxn2htgkjJn",
			"issuedAt":       "2022-01-27T17:09:38.578Z",
			"chainId":        "1",
			"expirationTime": "2100-01-07T14:31:43.952Z",
			"signature":      "0xdc35c7f8ba2720df052e0092556456127f00f7707eaa8e3bbff7e56774e7f2e05a093cfc9e02964c33d86e8e066e221b7d153d27e5a2e97ccd5ca7d3f2ce06cb1b",
		},
	}

	for k, v := range cases {
		message := InitMessage(
			v["domain"].(string),
			v["address"].(string),
			v["uri"].(string),
			v["version"].(string),
			*InitMessageOptions(v),
		)

		_, err := message.Verify(v["signature"].(string))

		assert.Nil(t, err, k)
	}
}
