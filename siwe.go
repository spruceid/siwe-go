package siwe

import (
	"fmt"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func InitMessageOptions(options map[string]interface{}) *MessageOptions {
	var issuedAt string
	if val, ok := options["issuedAt"]; ok {
		switch val.(type) {
		case time.Time:
			issuedAt = val.(time.Time).UTC().Format(time.RFC3339)
		case string:
			issuedAt = val.(string)
		}
	} else {
		issuedAt = time.Now().UTC().Format(time.RFC3339)
	}

	var nonce string
	if val, ok := options["nonce"]; ok {
		nonce = val.(string)
	} else {
		nonce = GenerateNonce()
	}

	var chainId string
	if val, ok := options["chainId"]; ok {
		chainId = val.(string)
	} else {
		chainId = "1"
	}

	var statement *string
	if val, ok := options["statement"]; ok {
		value := val.(string)
		statement = &value
	}

	var expirationTime *string
	if val, ok := options["expirationTime"]; ok {
		var value string
		switch val.(type) {
		case time.Time:
			value = val.(time.Time).UTC().Format(time.RFC3339)
		case string:
			value = val.(string)
		}
		expirationTime = &value
	}

	var notBefore *string
	if val, ok := options["notBefore"]; ok {
		var value string
		switch val.(type) {
		case time.Time:
			value = val.(time.Time).UTC().Format(time.RFC3339)
		case string:
			value = val.(string)
		}
		notBefore = &value
	}

	var requestID *string
	if val, ok := options["requestId"]; ok {
		value := val.(string)
		requestID = &value
	}

	var resources []string
	if val, ok := options["resources"]; ok {
		switch val.(type) {
		case []string:
			resources = val.([]string)
		case string:
			resources = strings.Split(val.(string), "\n- ")[1:]
		}
	}

	return &MessageOptions{
		IssuedAt: &issuedAt,
		Nonce:    &nonce,
		ChainID:  &chainId,

		Statement:      statement,
		ExpirationTime: expirationTime,
		NotBefore:      notBefore,
		RequestID:      requestID,
		Resources:      resources,
	}
}

func InitMessage(domain, address, uri, version string, options MessageOptions) *Message {
	return &Message{
		Domain:         domain,
		Address:        address,
		URI:            uri,
		Version:        version,
		MessageOptions: options,
	}
}

func GenerateNonce() string {
	return uniuri.NewLen(16)
}

func ParseMessage(message string) *Message {
	match := SIWE_MESSAGE.FindStringSubmatch(message)
	result := make(map[string]interface{})
	for i, name := range SIWE_MESSAGE.SubexpNames() {
		if i != 0 && name != "" && match[i] != "" {
			result[name] = match[i]
		}
	}

	return &Message{
		Domain:         result["domain"].(string),
		Address:        result["address"].(string),
		URI:            result["uri"].(string),
		Version:        result["version"].(string),
		MessageOptions: *InitMessageOptions(result),
	}
}

func (m *Message) ValidateMessage(signature string) (bool, error) {
	if !isEmpty(m.ExpirationTime) {
		expirationTime, err := time.Parse(time.RFC3339, *m.ExpirationTime)
		if err != nil {
			return false, err
		}
		if time.Now().UTC().After(expirationTime) {
			return false, &ExpiredMessage{"Message expired"}
		}
	}

	if !isEmpty(m.NotBefore) {
		notBefore, err := time.Parse(time.RFC3339, *m.NotBefore)
		if err != nil {
			return false, err
		}
		if time.Now().UTC().Before(notBefore) {
			return false, &InvalidMessage{"Message not yet valid"}
		}
	}

	if isEmpty(&signature) {
		return false, &InvalidSignature{"Signature cannot be empty"}
	}

	hash := crypto.Keccak256Hash([]byte(m.PrepareMessage()))

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return false, &InvalidSignature{"Failed to decode signature"}
	}

	pkey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return false, &InvalidSignature{"Failed to recover public key from signature"}
	}

	address := crypto.PubkeyToAddress(*pkey)

	if address.String() != m.Address {
		return false, &InvalidSignature{"Signer address must match message address"}
	}

	return true, nil
}

func (m *Message) PrepareMessage() string {
	greeting := fmt.Sprintf("%s wants you to sign in with your Ethereum account:", m.Domain)
	headerArr := []string{greeting, m.Address}

	if isEmpty(m.Statement) {
		headerArr = append(headerArr, "\n")
	} else {
		headerArr = append(headerArr, fmt.Sprintf("\n%s\n", *m.Statement))
	}

	header := strings.Join(headerArr, "\n")

	uri := fmt.Sprintf("URI: %s", m.URI)
	version := fmt.Sprintf("Version: %s", m.Version)
	chainId := fmt.Sprintf("Chain ID: %s", *m.ChainID)
	nonce := fmt.Sprintf("Nonce: %s", *m.Nonce)
	issuedAt := fmt.Sprintf("Issued At: %s", *m.IssuedAt)

	bodyArr := []string{uri, version, chainId, nonce, issuedAt}

	if !isEmpty(m.ExpirationTime) {
		value := fmt.Sprintf("Expiration Time: %s", *m.ExpirationTime)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.NotBefore) {
		value := fmt.Sprintf("Not Before: %s", *m.NotBefore)
		bodyArr = append(bodyArr, value)
	}

	if !isEmpty(m.RequestID) {
		value := fmt.Sprintf("Request ID: %s", *m.RequestID)
		bodyArr = append(bodyArr, value)
	}

	if len(m.Resources) > 0 {
		resourcesArr := make([]string, len(m.Resources))
		for i, v := range m.Resources {
			resourcesArr[i] = fmt.Sprintf("- %s", v)
		}

		resources := strings.Join(resourcesArr, "\n")
		value := fmt.Sprintf("Resources:\n%s", resources)

		bodyArr = append(bodyArr, value)
	}

	body := strings.Join(bodyArr, "\n")

	return strings.Join([]string{header, body}, "\n")
}
