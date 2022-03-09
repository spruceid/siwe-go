package siwe

import (
	"crypto/ecdsa"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dchest/uniuri"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/relvacode/iso8601"
)

type MalformedMessage struct{ string }
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

type Message struct {
	domain  string
	address common.Address
	uri     string
	version string

	statement *string
	nonce     *string
	chainID   int

	issuedAt       string
	expirationTime *string
	notBefore      *string

	requestID *string
	resources []string
}

func parseTimestamp(fields map[string]interface{}, key string) (*string, error) {
	var value string

	if val, ok := fields[key]; ok {
		switch val.(type) {
		case time.Time:
			value = val.(time.Time).UTC().Format(time.RFC3339)
		case string:
			_, err := iso8601.ParseString(val.(string))
			if err != nil {
				return nil, &InvalidMessage{fmt.Sprintf("Invalid format for field `%s`", key)}
			}
			value = val.(string)
		default:
			return nil, &InvalidMessage{fmt.Sprintf("`%s` must be either an ISO8601 formatted string or time.Time", key)}
		}
	}

	if value == "" {
		return nil, nil
	}

	return &value, nil
}

func InitMessage(domain, address, uri, version string, options map[string]interface{}) (*Message, error) {
	var statement *string
	if val, ok := options["statement"]; ok {
		value := val.(string)
		statement = &value
	}

	var nonce *string
	if val, ok := options["nonce"]; ok {
		value := val.(string)
		nonce = &value
	} else {
		value := GenerateNonce()
		nonce = &value
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
	if val, ok := options["requestId"]; ok {
		value := val.(string)
		requestID = &value
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
		uri:     uri,
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

func (m *Message) GetDomain() string {
	return m.domain
}

func (m *Message) GetAddress() common.Address {
	return m.address
}

func (m *Message) GetURI() string {
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

func (m *Message) GetNonce() *string {
	if m.nonce != nil {
		ret := *m.nonce
		return &ret
	}
	return nil
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

func (m *Message) GetResources() []string {
	return m.resources
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
	data := []byte(m.PrepareMessage())
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

	}

	return m.VerifyEIP191(signature)
}

func (m *Message) String() string {
	return m.PrepareMessage()
}

func (m *Message) PrepareMessage() string {
	greeting := fmt.Sprintf("%s wants you to sign in with your Ethereum account:", m.domain)
	headerArr := []string{greeting, m.address.String()}

	if isEmpty(m.statement) {
		headerArr = append(headerArr, "\n")
	} else {
		headerArr = append(headerArr, fmt.Sprintf("\n%s\n", *m.statement))
	}

	header := strings.Join(headerArr, "\n")

	uri := fmt.Sprintf("URI: %s", m.uri)
	version := fmt.Sprintf("Version: %s", m.version)
	chainId := fmt.Sprintf("Chain ID: %d", m.chainID)
	nonce := fmt.Sprintf("Nonce: %s", *m.nonce)
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
