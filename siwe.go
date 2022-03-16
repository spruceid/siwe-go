package siwe

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func InitMessage(domain, address, uri, version string, options map[string]interface{}) (*Message, error) {
	validateURI, err := url.Parse(uri)
	if err != nil {
		return nil, &InvalidMessage{"Invalid format for field `uri`"}
	}

	var statement *string
	if val, ok := options["statement"]; ok {
		value := val.(string)
		statement = &value
	}

	var nonce string
	if val, ok := isStringAndNotEmpty(options, "nonce"); ok {
		nonce = *val
	} else {
		return nil, &InvalidMessage{"Missing or empty `nonce` property"}
	}

	var chainId int
	if val, ok := options["chainId"]; ok {
		switch val.(type) {
		case int:
			chainId = val.(int)
		case string:
			parsed, err := strconv.Atoi(val.(string))
			if err != nil {
				return nil, &InvalidMessage{"Invalid format for field `chainId`, must be an integer"}
			}
			chainId = parsed
		default:
			return nil, &InvalidMessage{"`chainId` must be a string or a integer"}
		}
	} else {
		chainId = 1
	}

	var issuedAt string
	timestamp, err := parseTimestamp(options, "issuedAt")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		issuedAt = *timestamp
	} else {
		issuedAt = time.Now().UTC().Format(time.RFC3339)
	}

	var expirationTime *string
	timestamp, err = parseTimestamp(options, "expirationTime")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		expirationTime = timestamp
	}

	var notBefore *string
	timestamp, err = parseTimestamp(options, "notBefore")
	if err != nil {
		return nil, err
	}

	if timestamp != nil {
		notBefore = timestamp
	}

	var requestID *string
	if val, ok := isStringAndNotEmpty(options, "requestId"); ok {
		requestID = val
	}

	var resources []string
	if val, ok := options["resources"]; ok {
		switch val.(type) {
		case []string:
			resources = val.([]string)
		default:
			return nil, &InvalidMessage{"`resources` must be a []string"}
		}
	}

	return &Message{
		domain:  domain,
		address: common.HexToAddress(address),
		uri:     *validateURI,
		version: version,

		statement: statement,
		nonce:     nonce,
		chainID:   chainId,

		issuedAt:       issuedAt,
		expirationTime: expirationTime,
		notBefore:      notBefore,

		requestID: requestID,
		resources: resources,
	}, nil
}

func parseMessage(message string) (map[string]interface{}, error) {
	match := _SIWE_MESSAGE.FindStringSubmatch(message)

	if match == nil {
		return nil, &InvalidMessage{"Message could not be parsed"}
	}

	result := make(map[string]interface{})
	for i, name := range _SIWE_MESSAGE.SubexpNames() {
		if i != 0 && name != "" && match[i] != "" {
			result[name] = match[i]
		}
	}

	originalAddress := result["address"].(string)
	parsedAddress := common.HexToAddress(originalAddress)
	if originalAddress != parsedAddress.String() {
		return nil, &InvalidMessage{"Address must be in EIP-55 format"}
	}

	if val, ok := result["resources"]; ok {
		result["resources"] = strings.Split(val.(string), "\n- ")[1:]
	}

	return result, nil
}

func ParseMessage(message string) (*Message, error) {
	result, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	parsed, err := InitMessage(
		result["domain"].(string),
		result["address"].(string),
		result["uri"].(string),
		result["version"].(string),
		result,
	)

	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func (m *Message) eip191Hash() common.Hash {
	// Ref: https://stackoverflow.com/questions/49085737/geth-ecrecover-invalid-signature-recovery-id
	data := []byte(m.String())
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func (m *Message) ValidNow() (bool, error) {
	return m.ValidAt(time.Now().UTC())
}

func (m *Message) ValidAt(when time.Time) (bool, error) {
	if m.expirationTime != nil {
		if time.Now().UTC().After(*m.getExpirationTime()) {
			return false, &ExpiredMessage{"Message expired"}
		}
	}

	if m.notBefore != nil {
		if time.Now().UTC().Before(*m.getNotBefore()) {
			return false, &InvalidMessage{"Message not yet valid"}
		}
	}

	return true, nil
}

func (m *Message) VerifyEIP191(signature string) (*ecdsa.PublicKey, error) {
	if isEmpty(&signature) {
		return nil, &InvalidSignature{"Signature cannot be empty"}
	}

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, &InvalidSignature{"Failed to decode signature"}
	}

	// Ref:https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sigBytes[64] != 27 && sigBytes[64] != 28 {
		return nil, &InvalidSignature{"Invalid signature recovery byte"}
	}
	sigBytes[64] -= 27

	pkey, err := crypto.SigToPub(m.eip191Hash().Bytes(), sigBytes)
	if err != nil {
		return nil, &InvalidSignature{"Failed to recover public key from signature"}
	}

	address := crypto.PubkeyToAddress(*pkey)

	if address != m.address {
		return nil, &InvalidSignature{"Signer address must match message address"}
	}

	return pkey, nil
}

func (m *Message) Verify(signature string, nonce *string, timestamp *time.Time) (*ecdsa.PublicKey, error) {
	var err error

	if timestamp != nil {
		_, err = m.ValidAt(*timestamp)
	} else {
		_, err = m.ValidNow()
	}

	if err != nil {
		return nil, err
	}

	if nonce != nil {
		if m.GetNonce() == *nonce {
			return nil, &InvalidSignature{"Message nonce doesn't match"}
		}
	}

	return m.VerifyEIP191(signature)
}

func (m *Message) prepareMessage() string {
	greeting := fmt.Sprintf("%s wants you to sign in with your Ethereum account:", m.domain)
	headerArr := []string{greeting, m.address.String()}

	if isEmpty(m.statement) {
		headerArr = append(headerArr, "\n")
	} else {
		headerArr = append(headerArr, fmt.Sprintf("\n%s\n", *m.statement))
	}

	header := strings.Join(headerArr, "\n")

	uri := fmt.Sprintf("URI: %s", m.uri.String())
	version := fmt.Sprintf("Version: %s", m.version)
	chainId := fmt.Sprintf("Chain ID: %d", m.chainID)
	nonce := fmt.Sprintf("Nonce: %s", m.nonce)
	issuedAt := fmt.Sprintf("Issued At: %s", m.issuedAt)

	bodyArr := []string{uri, version, chainId, nonce, issuedAt}

	if !isEmpty(m.expirationTime) {
		value := fmt.Sprintf("Expiration Time: %s", *m.expirationTime)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.notBefore) {
		value := fmt.Sprintf("Not Before: %s", *m.notBefore)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.requestID) {
		value := fmt.Sprintf("Request ID: %s", *m.requestID)
		bodyArr = append(bodyArr, value)
	}

	if len(m.resources) > 0 {
		resourcesArr := make([]string, len(m.resources))
		for i, v := range m.resources {
			resourcesArr[i] = fmt.Sprintf("- %s", v)
		}

		resources := strings.Join(resourcesArr, "\n")
		value := fmt.Sprintf("Resources:\n%s", resources)

		bodyArr = append(bodyArr, value)
	}

	body := strings.Join(bodyArr, "\n")

	return strings.Join([]string{header, body}, "\n")
}

func (m *Message) String() string {
	return m.prepareMessage()
}
