package jwk

import (
	"fmt"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pkg/errors"
)

var testKid = "QzQ4QzExMzNENkJCMThDNjNCN0ZEQjQwQkEwNUFFMzY1NDU5QzcxNA"
var testKey = "MIIDCzCCAfOgAwIBAgIJDLLYwRgUea6sMA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMTGHRvcHNvbHV0aW9uLmV1LmF1dGgwLmNvbTAeFw0xODEwMTExNTQwMzBaFw0zMjA2MTkxNTQwMzBaMCMxITAfBgNVBAMTGHRvcHNvbHV0aW9uLmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN5PN+xxZOmFWWztp3xFNjnjCTMAu+ZBSCj9h5do6VUt22uPlshjAWCA9BnrbBMhdGR38Eg8XXpMntvXFJvw9I0dvqdmbBY/dM7TwDc8rOz4qsXCtuJSnhrOex/FemdsZ15hs3LAHfddKKo8tZ2Hs1fX+K90YdFMURopjjL9F1jXGGvIs1Zi9yZTKYOVFbX0BykzT9JkSx44T7puvzUqmBUJyrdpXalouNuE6iruFm7WdlMoK2LOi9yCAwUa5eNMgLxRnQbk6QvCvgnBfWcTQ6n4Y3UzK+RgJ28UGRhs03m9Pfov9kov7ZSruinG20inQ9xeSbBxCHNy3r0RSkiz9XcCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6wLAfnF3rypEQML/n6BmpoggxfowDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQCcvCc1chcjFcQ75PtcTqC9AiDrmryJWyj9apXbAwaTV47KAkN5PvA14OKcQBTlJZXRcRq/QAimMLZna3au6lsr+/SkeqE2n26j9eG3ZUYb8HQ+mHKMzsqcBTMLFsMeQ0f7Y18EakYu6kGE79jdgjr96TuurTwMKxc2dbkivSs3Zi+fQoZrjQ0EqNuCCNiZUA9MbcHrYB18mk31RvMVARJMdY+eQeeR2rSFoSDnn/DO4Oy745c/VOIq7Cigh/GAdH2M5+Jv6SalqH2OiwMlfH72pyd6j+OjfwtI6cyY8BRV4itNCvp2Pf9wyUPjm1Lq7YAVWHySNDPKao2OVn9Af4/A"

func getTestCerts() (*Certs, error) {
	return parseCerts(&jwks{Keys: []jwk{
		{
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			X5c: []string{testKey},
			Kid: testKid,
		}}}, 10800*time.Second)
}
func TestParseCerts(t *testing.T) {
	parsedCerts, err := getTestCerts()
	if err != nil {
		t.Error(err)
		return
	}

	expectedCerts := &Certs{
		Keys: map[string]string{
			testKid: testKey,
		},
		Expiry: time.Now().Add(time.Second * 10800),
	}

	if err := equalCerts(expectedCerts, parsedCerts); err != nil {
		t.Error(err)
	}
}

func equalCerts(a, b *Certs) error {
	for id := range a.Keys {
		err := equalsRSAKeys(a.Keys, b.Keys, id)
		if err != nil {
			return err
		}
	}
	// simply check for second-granurality precision
	if a.Expiry.Unix() != b.Expiry.Unix() {
		return fmt.Errorf("expire dates mismatch: %d != %d", a.Expiry.Unix(), b.Expiry.Unix())
	}
	return nil
}

func TestGetKeys(t *testing.T) {
	testCerts, err := getTestCerts()
	if err != nil {
		t.Fatal(err)
	}
	j := JSONWebKeys{cachedCerts: testCerts}

	certs, err := j.GetKeys()
	if err != nil {
		t.Error(err)
		return
	}

	cachedCerts, err := j.GetKeys()
	if err != nil {
		t.Error(err)
		return
	}

	if certs != cachedCerts {
		t.Error("expecting same instance for cached certs")
	}
}

func TestWithPemHeaders(t *testing.T) {
	key := "AVERYREALKEY"
	expected := "-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----"
	if expected != withPEMHeaders(key) {
		t.Fatal("unexpected output of withPEMHeaders")
	}
}

func TestGetKey(t *testing.T) {
	testCerts, err := getTestCerts()
	if err != nil {
		t.Fatal(err)
	}
	j := JSONWebKeys{cachedCerts: testCerts}

	token := jwt.JSONWebToken{Headers: []jose.Header{jose.Header{KeyID: testKid}}}

	key, err := j.GetKey(&token)
	if string(key) != withPEMHeaders(testKey) {
		t.Fatal(errors.New("token mismatch"))
	}
}

func equalsRSAKeys(a, b map[string]string, id string) error {

	key, ok := a[id]
	if !ok {
		return errors.New("key " + id + " does not exists in a")
	}

	key2, ok := b[id]
	if !ok {
		return errors.New("key " + id + " does not exists in b")
	}

	if key != key2 {
		return errors.New("key " + id + " is different")
	}
	return nil
}
