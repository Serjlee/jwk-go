# jwk.go
Package jwk offer useful functions to handle, fetch and cache JWT public keys from a public
JSON Web Key store (IETF RFC 7517, see: https://tools.ietf.org/html/rfc7517)

This package does not currently support the whole standard, but just the slim subset needed
for working with the Auth0 Json Web Key Stores: https://auth0.com/docs/jwks

## Example
```go
package main

import (
	"fmt"
	"log"

	"github.com/serjlee/jwk.go"
	"gopkg.in/square/go-jose.v2/jwt"
)

func main() {
	token := "your.jwt.token"
	t, err := jwt.ParseSigned(token)
	if err != nil {
		log.Fatal(err)
	}
	keys := jwk.JSONWebKeys{
		JWKURL: "https://{your-auth0-domain}/.well-known/jwks.json",
	}
	key, err := keys.GetKey(t)
	if err != nil {
		log.Fatal(err)
	}
    // that's your public key
	fmt.Println(string(key))
}
```