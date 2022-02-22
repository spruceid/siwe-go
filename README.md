# Sign-In with Ethereum

This package provides a pure Go implementation of EIP-4361: Sign In With Ethereum.

## Installation

SIWE can be easily installed in any Go project by running:

```bash
go get -u github.com/spruceid/siwe-go
```

## Usage

SIWE exposes a Message struct which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done via the `siwe.ParseMessage` function:

```go
message := siwe.ParseMessage(messageStr)
```

### Verifying and Authenticating a SIWE Message

Verification and Authentication is performed via EIP-191,
using the address field of the Message as the expected signer.
This returns the Ethereum public key of the signer:

```go
var publicKey *ecdsa.PublicKey
var err error

publicKey, err = message.VerifyEIP191(signature)
```

The time constraints (expiry and not-before) can also be
validated, at current or particular times:

```go
if message.ValidNow() {
  // ...
}

// equivalent to

if message.ValidAt(time.Now().UTC()) {
  // ...
}
```

Combined verification of time constraints and authentication
can be done in a single call with verify:

```go
var publicKey *ecdsa.PublicKey
var err error

publicKey, err = message.Verify(signature)
```

### Serialization of a SIWE Message

Message instances can also be serialized as their EIP-4361
string representations via the `PrepareMessage` method:

```go
fmt.Printf("%s", message.PrepareMessage())
```

## Signing Messages from Go code

To sign messages directly from Go code, you will need to do it
like shown below to correctly follow the `personal_sign` format.

```go
func signHash(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func signMessage(message string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sign := signHash([]byte(message))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)

	if err != nil {
		return nil, err
	}

	signature[64] += 27
	return signature, nil
}
```

## Disclaimer 

Our Go library for Sign-In with Ethereum has not yet undergone a formal security 
audit. We welcome continued feedback on the usability, architecture, and security 
of this implementation.

## See Also

- [Sign-In with Ethereum: TypeScript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://login.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
