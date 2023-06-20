package grants

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/pkg/oauth"
)

// TestAuthorizationCodeGrant produces JWT via authorization code grant flow (link to rfc)
func TestAuthorizationCodeGrant(t *testing.T) {
	// TODO - test authorization code grant flow ...
	cfg := config.NewConfig("internal/config/test.yml")

	// generate an RSA key pair
	private, err := rsa.GenerateKey(rand.Reader, cfg.OAuth.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	// create issuer for testing purposes
	name := cfg.OAuth.Issuer
	hour, _ := time.ParseDuration(cfg.OAuth.TokenTTL)
	issuer := oauth.NewSimpleIssuer(private, name+cfg.OAuth.JWKS, cfg.OAuth.Audience, time.Now(), hour)

	// create a granter
	name = cfg.Server.Host + ":" + cfg.Server.Port
	minutes, _ := time.ParseDuration("10m")
	granter := NewGranter(issuer, minutes, 8, name+"/device")

	server := httptest.NewServer(http.HandlerFunc(granter.AuthorizationCodeHandler))
	server.Start()
	defer server.Close()

	// TODO - implement client portion of authorization code grant!
	// ex step 1: GET http://localhost:8081/authorize?client_id=friday&response_type=code&redirect_uri=https://client.example.io
	// DO NOT follow HTTP 302, simply read response to get authorization code
	// ex step 2: POST http://localhost:8081/jwt?grant_type=authorization_code&client_id=friday&code=7deced1b-edac-439d-b990-c6cee1df8fd2&redirect_uri=https://client.example.io
	// remember HTTP headers ... Content-Type application/x-www-form-urlencoded
}
