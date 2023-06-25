package grants

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/pkg/oauth"
)

// TestAuthorizationCodeGrant produces JWT via authorization code grant flow (link to rfc)
func TestAuthorizationCodeGrant(t *testing.T) {
	// TODO - test authorization code grant flow ...
	logger := log.Default()

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
	granter := NewGranter(issuer, minutes, 8, name)

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", granter.AuthorizationCodeHandler)
	mux.HandleFunc("/jwt", granter.AuthorizationTokenHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	rserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			logger.Println(err)
		}

		logger.Println(string(requestDump))

		q := r.URL.Query()
		code := q["code"][0] // Grabs the first code given back
		logger.Println("auth code: " + code)

		w.Header().Add("code", code)
		w.WriteHeader(200)
	}))

	defer rserver.Close()

	client := http.Client{}
	client_id := "friday"

	authCodeEndpoint := fmt.Sprintf("%v/authorize?client_id=%v&response_type=code&redirect_uri=%v", server.URL, client_id, rserver.URL)
	// logger.Println("auth code endpoint: " + authCodeEndpoint)

	getReq, err := http.NewRequest("GET", authCodeEndpoint, nil)
	if err != nil {
		log.Printf("%v", err)
	}

	getReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(getReq)
	if err != nil {
		log.Printf("%v", err)
	}

	logger.Printf("get status code: [%v]", resp.StatusCode)

	code := resp.Header.Get("code")

	jwtEndpoint := fmt.Sprintf("%v/jwt?grant_type=authorization_code&client_id=%v&code=%v&response_type=code&redirect_uri=%v", server.URL, client_id, code, rserver.URL)
	logger.Println("jwt endpoint: " + jwtEndpoint)

	postReq, err := http.NewRequest("POST", jwtEndpoint, nil)
	if err != nil {
		log.Printf("%v", err)
	}

	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(postReq)
	if err != nil {
		log.Printf("%v", err)
	}

	logger.Println("status code: " + resp.Status)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%v", err)
	}

	defer resp.Body.Close()

	logger.Printf("response body: %v", string(body))
}
