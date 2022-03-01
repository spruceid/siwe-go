package siwe

import (
	"crypto/ecdsa"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type ParsingFailed struct{ string }
type ExpiredMessage struct{ string }
type InvalidMessage struct{ string }
type InvalidSignature struct{ string }

func (m *ParsingFailed) Error() string {
	return "Expired Message"
}

func (m *ExpiredMessage) Error() string {
	return "Expired Message"
}

func (m *InvalidMessage) Error() string {
	return "Invalid Message"
}

func (m *InvalidSignature) Error() string {
	return fmt.Sprintf("Invalid Signature: %s", m.string)
}

type MessageOptions struct {
	IssuedAt *string `json:"issuedAt"`
	Nonce    *string `json:"nonce"`
	ChainID  *string `json:"chainId"`

	Statement      *string  `json:"statement,omitempty"`
	ExpirationTime *string  `json:"expirationTime,omitempty"`
	NotBefore      *string  `json:"notBefore,omitempty"`
	RequestID      *string  `json:"requestId,omitempty"`
	Resources      []string `json:"resources,omitempty"`
}

type Message struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
	URI     string `json:"uri"`
	Version string `json:"version"`
	MessageOptions
}

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

func isEmpty(str *string) bool {
	return str == nil || len(strings.TrimSpace(*str)) == 0
}

const _SIWE_DOMAIN = "^(?P<domain>([^?#]*)) wants you to sign in with your Ethereum account:\\n"
const _SIWE_ADDRESS = "(?P<address>0x[a-zA-Z0-9]{40})\\n\\n"
const _SIWE_STATEMENT = "((?P<statement>[^\\n]+)\\n)?\\n"
const _SIWE_URI = "(([^:?#]+):)?(([^?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))"

var _SIWE_URI_LINE = fmt.Sprintf("URI: (?P<uri>%s?)\\n", _SIWE_URI)

const _SIWE_VERSION = "Version: (?P<version>1)\\n"
const _SIWE_CHAIN_ID = "Chain ID: (?P<chainId>[0-9]+)\\n"
const _SIWE_NONCE = "Nonce: (?P<nonce>[a-zA-Z0-9]{8,})\\n"
const _SIWE_DATETIME = "([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?(([Zz])|([\\+|\\-]([01][0-9]|2[0-3]):[0-5][0-9]))"

var _SIWE_ISSUED_AT = fmt.Sprintf("Issued At: (?P<issuedAt>%s)", _SIWE_DATETIME)
var _SIWE_EXPIRATION_TIME = fmt.Sprintf("(\\nExpiration Time: (?P<expirationTime>%s))?", _SIWE_DATETIME)
var _SIWE_NOT_BEFORE = fmt.Sprintf("(\\nNot Before: (?P<notBefore>%s))?", _SIWE_DATETIME)

const _SIWE_REQUEST_ID = "(\\nRequest ID: (?P<requestId>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?"

var _SIWE_RESOURCES = fmt.Sprintf("(\\nResources:(?P<resources>(\\n- %s?)+))?$", _SIWE_URI)

var _SIWE_MESSAGE = regexp.MustCompile(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s",
	_SIWE_DOMAIN,
	_SIWE_ADDRESS,
	_SIWE_STATEMENT,
	_SIWE_URI_LINE,
	_SIWE_VERSION,
	_SIWE_CHAIN_ID,
	_SIWE_NONCE,
	_SIWE_ISSUED_AT,
	_SIWE_EXPIRATION_TIME,
	_SIWE_NOT_BEFORE,
	_SIWE_REQUEST_ID,
	_SIWE_RESOURCES))

func ParseMessage(message string) (*Message, error) {
	match := _SIWE_MESSAGE.FindStringSubmatch(message)

	if match == nil {
		return nil, &ParsingFailed{"Message could not be parsed"}
	}

	result := make(map[string]interface{})
	for i, name := range _SIWE_MESSAGE.SubexpNames() {
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
	}, nil
}

func signHash(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func (m *Message) getLowercaseAddress() string {
	return strings.ToLower(m.Address)
}

func (m *Message) ValidNow() (bool, error) {
	return m.ValidAt(time.Now().UTC())
}

func (m *Message) ValidAt(when time.Time) (bool, error) {
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

	return true, nil
}

func (m *Message) VerifyEIP191(signature string) (*ecdsa.PublicKey, error) {
	if isEmpty(&signature) {
		return nil, &InvalidSignature{"Signature cannot be empty"}
	}

	// Ref: https://stackoverflow.com/questions/49085737/geth-ecrecover-invalid-signature-recovery-id
	data := m.PrepareMessage()
	hash := signHash([]byte(data))

	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return nil, &InvalidSignature{"Failed to decode signature"}
	}

	// Ref:https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sigBytes[64] != 27 && sigBytes[64] != 28 {
		return nil, &InvalidSignature{"Invalid signature bytes"}
	}
	sigBytes[64] -= 27

	pkey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return nil, &InvalidSignature{"Failed to recover public key from signature"}
	}

	address := crypto.PubkeyToAddress(*pkey)

	addressLowercase := strings.ToLower(address.String())

	if addressLowercase != m.getLowercaseAddress() {
		return nil, &InvalidSignature{"Signer address must match message address"}
	}

	return pkey, nil
}

func (m *Message) Verify(signature string) (*ecdsa.PublicKey, error) {
	_, err := m.ValidNow()

	if err != nil {
		return nil, err
	}

	return m.VerifyEIP191(signature)
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
