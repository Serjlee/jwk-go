// Package jwk offer useful functions to handle, fetch and cache JWT public keys from a public
// JSON Web Key store (IETF RFC 7517, see: https://tools.ietf.org/html/rfc7517)
//
// This package does not currently support the whole standard, but just the subset needed
// for working with the Auth0 Json Web Key Stores: https://auth0.com/docs/jwks
//
// Example:
//
// package main

// import (
// 	"fmt"
// 	"log"

// 	"github.com/serjlee/jwk.go"
// 	"github.com/go-jose/go-jose/v3/jwt"
// )

//	func main() {
//		token := "your.jwt.token"
//		t, err := jwt.ParseSigned(token)
//		if err != nil {
//			log.Fatal(err)
//		}
//		keys := jwk.JSONWebKeys{
//			JWKURL: "https://{your-auth0-domain}/.well-known/jwks.json",
//		}
//		key, err := keys.GetKey(t.Headers[0].KeyID)
//		if err != nil {
//			log.Fatal(err)
//		}
//	 // that's your public key
//		fmt.Println(string(key))
//		// you can use an helper function to get it with PEM headers
//		fmt.Println(key.PEM())
//	}
package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// Certs holds a map of KeyID-RSA public key and their expiration time
type Certs struct {
	Keys   map[string]Key
	Expiry time.Time
}

// ToSlice returns the keys in a slice
func (c Certs) ToSlice() []Key {
	keys := []Key{}
	for _, v := range c.Keys {
		keys = append(keys, v)
	}
	return keys
}

// jwks maps a JSON Web Key Store to a struct
type jwks struct {
	Keys []Key `json:"keys"`
}

// Key maps a JSON Web Key to a struct
type Key struct {
	// alg is the algorithm: it's currently ignored: only RSA is supported
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// Empty tells if the struct is empty
func (k Key) Empty() bool {
	return k.Alg == ""
}

// PEM adds the PEM headers to the given key
func (k Key) PEM() string {
	if len(k.X5c) < 1 {
		return ""
	}
	return "-----BEGIN CERTIFICATE-----\n" + k.X5c[0] + "\n-----END CERTIFICATE-----"
}

// RSA returns the key as an rsa.PublicKey
func (k Key) RSA() *rsa.PublicKey {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		panic(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		panic(err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}
}

// JSONWebKeys fetches and caches RSA public keys from a given JSON Web Key Store
// it currently expects the same shape of the default Auth0 Key Stores: with defined public keys
// in the X5c fields
type JSONWebKeys struct {
	// JWKURL is the URL to the JWK definition, i.e.: https://YOUR_AUTH0_DOMAIN/.well-known/jwks.json
	JWKURL string

	// DefaultCacheAge is the default cache duration for certs, if the resource does not set a max-age cache header
	// auth0 suggest about 10 hours, but the keys aren't currently expected to expire
	// see https://github.com/auth0/node-jwks-rsa#caching
	DefaultCacheAge time.Duration

	// Client is the HTTP client used while fetching the certs. If unset it will default to a Client with a 10-seconds timeout
	Client *http.Client

	// cachedCerts holds the latest fetched certs
	cachedCerts *Certs

	// certsMutex ensures no data races while reading and storing the JWKs
	certsMutex sync.RWMutex
}

// GetKeys returns RSA public keys from the JWK store
func (j *JSONWebKeys) GetKeys() (*Certs, error) {
	// Read from cache when defined and fresh
	j.certsMutex.RLock()
	certs := j.cachedCerts
	j.certsMutex.RUnlock()
	if certs != nil {
		if time.Now().Before(certs.Expiry) {
			return certs, nil
		}
	}

	// Fetch and write cache when not
	j.certsMutex.Lock()
	defer j.certsMutex.Unlock()

	res, cacheAge, err := j.fetchJWKS()
	if err != nil {
		return nil, err
	}

	parsedCerts, err := parseCerts(res, cacheAge)
	if err != nil {
		return nil, err
	}

	j.cachedCerts = parsedCerts

	return parsedCerts, nil
}

// GetCertificate finds a matching cert for the given JWT
func (j *JSONWebKeys) GetKey(keyId string) (Key, error) {
	var cert Key
	certs, err := j.GetKeys()
	if err != nil {
		return cert, err
	}

	var ok bool
	if cert, ok = certs.Keys[keyId]; !ok {
		return cert, errors.New("Unable to find the appropriate key.")
	}

	return cert, nil
}

// fetchJWKS fetches and parses the JWKS resource from the given URL
func (j *JSONWebKeys) fetchJWKS() (*jwks, time.Duration, error) {
	if j.Client == nil {
		j.Client = &http.Client{Timeout: time.Second * 10}
	}
	resp, err := j.Client.Get(j.JWKURL)
	if err != nil {
		return nil, 0, err
	}
	cacheControl := resp.Header.Get("cache-control")
	if j.DefaultCacheAge == 0 {
		j.DefaultCacheAge = time.Hour * 10
	}
	cacheAge := j.DefaultCacheAge
	if len(cacheControl) > 0 {
		re := regexp.MustCompile("max-age=([0-9]*)")
		match := re.FindAllStringSubmatch(cacheControl, -1)
		if len(match) > 0 {
			if len(match[0]) == 2 {
				maxAge := match[0][1]
				maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
				if err != nil {
					return nil, 0, err
				}
				cacheAge = time.Duration(maxAgeInt) * time.Second
			}
		}
	}

	res := &jwks{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, 0, err
	}

	return res, cacheAge, nil
}

// withPEMHeaders adds the PEM headers to the given key
func withPEMHeaders(key string) string {
	return "-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----"
}

// parseCerts looks for RSA public keys
func parseCerts(res *jwks, cacheAge time.Duration) (*Certs, error) {
	keys := map[string]Key{}
	for _, key := range res.Keys {
		if key.Use == "sig" && key.Kty == "RSA" {
			keys[key.Kid] = key
		}
	}
	return &Certs{
		Keys:   keys,
		Expiry: time.Now().Add(cacheAge),
	}, nil
}
