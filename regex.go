package siwe

import (
	"fmt"
	"regexp"
)

const SIWE_DOMAIN = "^(?P<domain>([^?#]*)) wants you to sign in with your Ethereum account:\\n"
const SIWE_ADDRESS = "(?P<address>0x[a-zA-Z0-9]{40})\\n\\n"
const SIWE_STATEMENT = "((?P<statement>[^\\n]+)\\n)?\\n"
const SIWE_URI = "(([^:?#]+):)?(([^?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))"

var SIWE_URI_LINE = fmt.Sprintf("URI: (?P<uri>%s?)\\n", SIWE_URI)

const SIWE_VERSION = "Version: (?P<version>1)\\n"
const SIWE_CHAIN_ID = "Chain ID: (?P<chainId>[0-9]+)\\n"
const SIWE_NONCE = "Nonce: (?P<nonce>[a-zA-Z0-9]{8,})\\n"
const SIWE_DATETIME = "([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?(([Zz])|([\\+|\\-]([01][0-9]|2[0-3]):[0-5][0-9]))"

var SIWE_ISSUED_AT = fmt.Sprintf("Issued At: (?P<issuedAt>%s)", SIWE_DATETIME)
var SIWE_EXPIRATION_TIME = fmt.Sprintf("(\\nExpiration Time: (?P<expirationTime>%s))?", SIWE_DATETIME)
var SIWE_NOT_BEFORE = fmt.Sprintf("(\\nNot Before: (?P<notBefore>%s))?", SIWE_DATETIME)

const SIWE_REQUEST_ID = "(\\nRequest ID: (?P<requestId>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?"

var SIWE_RESOURCES = fmt.Sprintf("(\\nResources:(?P<resources>(\\n- %s?)+))?$", SIWE_URI)

var SIWE_MESSAGE = regexp.MustCompile(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s",
	SIWE_DOMAIN,
	SIWE_ADDRESS,
	SIWE_STATEMENT,
	SIWE_URI_LINE,
	SIWE_VERSION,
	SIWE_CHAIN_ID,
	SIWE_NONCE,
	SIWE_ISSUED_AT,
	SIWE_EXPIRATION_TIME,
	SIWE_NOT_BEFORE,
	SIWE_REQUEST_ID,
	SIWE_RESOURCES))
