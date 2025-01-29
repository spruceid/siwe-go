package siwe

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func buildAuthority(uri *url.URL) string {
	authority := uri.Host
	if uri.User != nil {
		authority = fmt.Sprintf("%s@%s", uri.User.String(), authority)
	}
	return authority
}

func validateDomain(domain *string) (bool, error) {
	if isEmpty(domain) {
		return false, &InvalidMessage{"`domain` must not be empty"}
	}

	validateDomain, err := url.Parse(fmt.Sprintf("https://%s", *domain))
	if err != nil {
		return false, &InvalidMessage{"Invalid format for field `domain`"}
	}

	authority := buildAuthority(validateDomain)
	if authority != *domain {
		return false, &InvalidMessage{"Invalid format for field `domain`"}
	}

	return true, nil
}

func validateURI(uri *string) (*url.URL, error) {
	if isEmpty(uri) {
		return nil, &InvalidMessage{"`uri` must not be empty"}
	}

	validateURI, err := url.Parse(*uri)
	if err != nil {
		return nil, &InvalidMessage{"Invalid format for field `uri`"}
	}

	return validateURI, nil
}

// InitMessage creates a Message object with the provided parameters
func InitMessage(domain, address, uri, nonce string, options map[string]interface{}) (*Message, error) {
	if ok, err := validateDomain(&domain); !ok {
		return nil, err
	}

	if isEmpty(&address) {
		return nil, &InvalidMessage{"`address` must not be empty"}
	}

	validateURI, err := validateURI(&uri)
	if err != nil {
		return nil, err
	}

	if isEmpty(&nonce) {
		return nil, &InvalidMessage{"`nonce` must not be empty"}
	}

	var statement *string
	if val, ok := options["statement"]; ok {
		value := val.(string)
		statement = &value
	}

	var chainId int
	if val, ok := options["chainId"]; ok {
		switch tv := val.(type) {
		case float64:
			chainId = int(tv)
		case int:
			chainId = tv
		case string:
			parsed, err := strconv.Atoi(tv)
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

	var resources []url.URL
	if val, ok := options["resources"]; ok {
		resources, ok = val.([]url.URL)
		if !ok {
			return nil, &InvalidMessage{"`resources` must be a []url.URL"}
		}
	}

	return &Message{
		domain:  domain,
		address: common.HexToAddress(address),
		uri:     *validateURI,
		version: "1",

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

	domain, ok := result["domain"].(string)
	if !ok {
		return nil, &InvalidMessage{"`domain` must not be empty"}
	}
	if ok, err := validateDomain(&domain); !ok {
		return nil, err
	}

	uri, ok := result["uri"].(string)
	if !ok {
		return nil, &InvalidMessage{"`domain` must not be empty"}
	}
	if _, err := validateURI(&uri); err != nil {
		return nil, err
	}

	originalAddress := result["address"].(string)
	parsedAddress := common.HexToAddress(originalAddress)
	if originalAddress != parsedAddress.String() {
		return nil, &InvalidMessage{"Address must be in EIP-55 format"}
	}

	if val, ok := result["resources"]; ok {
		resourcesStr, ok := val.(string)
		if !ok {
			return nil, &InvalidMessage{fmt.Sprintf("resources is not a string but %T", val)}
		}
		resources := strings.Split(resourcesStr, "\n- ")
		if len(resources) < 1 {
			return nil, &InvalidMessage{"expected at least one resource"}
		}
		resources = resources[1:]
		validateResources := make([]url.URL, len(resources))
		for i, resource := range resources {
			validateResource, err := url.Parse(resource)
			if err != nil {
				return nil, &InvalidMessage{fmt.Sprintf("Invalid format for field `resources` at position %d: %s", i, err)}
			}
			validateResources[i] = *validateResource
		}
		result["resources"] = validateResources
	}

	return result, nil
}

// ParseMessage returns a Message object by parsing an EIP-4361 formatted string
func ParseMessage(message string) (*Message, error) {
	result, err := parseMessage(message)
	if err != nil {
		return nil, err
	}

	parsed, err := InitMessage(
		result["domain"].(string),
		result["address"].(string),
		result["uri"].(string),
		result["nonce"].(string),
		result,
	)

	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func (m *Message) eip191Hash() []byte {
	data := []byte(m.String())
	return accounts.TextHash(data)
}

// ValidNow validates the time constraints of the message at current time.
func (m *Message) ValidNow() (bool, error) {
	return m.ValidAt(time.Now().UTC())
}

// ValidAt validates the time constraints of the message at a specific point in time.
func (m *Message) ValidAt(when time.Time) (bool, error) {
	if m.expirationTime != nil {
		if when.After(*m.getExpirationTime()) {
			return false, &ExpiredMessage{"Message expired"}
		}
	}

	if m.notBefore != nil {
		if when.Before(*m.getNotBefore()) {
			return false, &InvalidMessage{"Message not yet valid"}
		}
	}

	return true, nil
}

// VerifyEIP191 validates the integrity of the object by matching it's signature.
func (m *Message) VerifyEIP191(signature string) (*ecdsa.PublicKey, error) {
	if isEmpty(&signature) {
		return nil, &InvalidSignature{"Signature cannot be empty"}
	}

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, &InvalidSignature{"Failed to decode signature"}
	}

	// Ref:https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	sigBytes[64] %= 27
	if sigBytes[64] != 0 && sigBytes[64] != 1 {
		return nil, &InvalidSignature{"Invalid signature recovery byte"}
	}

	pkey, err := crypto.SigToPub(m.eip191Hash(), sigBytes)
	if err != nil {
		return nil, &InvalidSignature{"Failed to recover public key from signature"}
	}

	address := crypto.PubkeyToAddress(*pkey)

	if address != m.address {
		return nil, &InvalidSignature{"Signer address must match message address"}
	}

	return pkey, nil
}

// Verify validates time constraints and integrity of the object by matching it's signature.
func (m *Message) Verify(signature string, domain *string, nonce *string, timestamp *time.Time) (*ecdsa.PublicKey, error) {
	var err error

	if timestamp != nil {
		_, err = m.ValidAt(*timestamp)
	} else {
		_, err = m.ValidNow()
	}

	if err != nil {
		return nil, err
	}

	if domain != nil {
		if m.GetDomain() != *domain {
			return nil, &InvalidSignature{"Message domain doesn't match"}
		}
	}

	if nonce != nil {
		if m.GetNonce() != *nonce {
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
			resourcesArr[i] = fmt.Sprintf("- %s", v.String())
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
