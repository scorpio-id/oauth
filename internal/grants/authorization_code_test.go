package grants

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/pkg/oauth"
	"github.com/stretchr/testify/assert"
)

// TestAuthorizationCodeGrant produces JWT via authorization code grant flow (link to rfc)
func TestAuthorizationCodeGrant(t *testing.T) {
	// TODO - test authorization code grant flow ...
	cfg := config.NewConfig("../config/test.yml")

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
	defer server.Close()

	// TODO - implement client portion of authorization code grant!

	client := http.Client{
		// Client Auto Follows Redirects but we want the redirecturi
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	// ex step 1: GET http://localhost:8081/authorize?client_id=friday&response_type=code&redirect_uri=https://client.example.io

	client_id := "friday"
	redirect_url := "https://client.example.io"

	authCodeEndpoint := fmt.Sprintf("%v/authorize?client_id=%v&response_type=code&redirect_uri=%v", server.URL, client_id, redirect_url)

	getReq, err := http.NewRequest("GET", authCodeEndpoint, nil)
	if err != nil{
		log.Printf("%v", err)
	}

	getReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(getReq)
	if  err != nil{
		log.Printf("%v", err)
	}

	// Makes sure response is a redirect
	assert.True(t, resp.StatusCode == 302)

	redirectUri, err := resp.Location()
	if  err != nil{
		log.Printf("%v", err)
	}

	// Extracting url code parameter
	u, err := url.Parse(redirectUri.String())
	if  err != nil{
		log.Printf("%v", err)
	}

	q := u.Query()
	authCode := q["code"][0] // Grabs the first code given back

	// ex step 2: POST http://localhost:8081/jwt?grant_type=authorization_code&client_id=friday&code=7deced1b-edac-439d-b990-c6cee1df8fd2&redirect_uri=https://client.example.io

	// ------ AUTHORIZATION ------

	jwtEndpoint := fmt.Sprintf("%v/jwt?grant_type=authorization_code&client_id=%v&code=%v&response_type=code&redirect_uri=%v", server.URL, client_id, authCode, redirect_url)

	postReq, err := http.NewRequest("POST", jwtEndpoint, nil)
	if err != nil{
		log.Printf("%v", err)
	}

	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(postReq)
	if  err != nil{
		log.Printf("%v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if  err != nil{
		log.Printf("%v", err)
	}
	defer resp.Body.Close()

	// GOING TO REDIRECT URI FOR SOME REASON

	fmt.Printf("%v",body)

}
