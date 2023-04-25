package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/grants"
	"github.com/scorpio-id/oauth/pkg/oauth"
)

// NewRouter creates a new mux router with applied server, oauth, and device grant configurations
func NewRouter(cfg config.Config) (*mux.Router, *grants.Granter) {
	// generate an RSA key pair
	private, err := rsa.GenerateKey(rand.Reader, cfg.OAuth.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	// create a simple oauth2 issuer which contains a JWT signer and matching JWKS
	// the name provided below becomes the 'iss' claim in minted access tokens
	// start time determines the 'nbf' claim
	// the TTL integer determines the lifetime of an access token in seconds
	// we are using plain http here strictly for example purposes
	name := cfg.OAuth.Issuer
	hour, _ := time.ParseDuration(cfg.OAuth.TokenTTL)
	issuer := oauth.NewSimpleIssuer(private, name+cfg.OAuth.JWKS, cfg.OAuth.Audience, time.Now(), hour)

	// FIXME create a device granter
	name = cfg.Server.Host + ":" + cfg.Server.Port
	minutes, _ := time.ParseDuration("10m")
	granter := grants.NewGranter(issuer, minutes, 8, name+"/device")

	// create gorilla mux router
	router := mux.NewRouter()

	// host oauth2 JWKS endpoint
	router.HandleFunc(cfg.OAuth.JWKS, issuer.JWKSHandler)

	// TODO - add routes for client_credentials grant
	// routes specific to RFC 8628 OAuth 2.0 Device Authorization Grant https://www.rfc-editor.org/rfc/rfc8628
	// router.HandleFunc("/device", granter.RegistrationHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/access_token", granter.AccessTokenHandler).Methods(http.MethodPost, http.MethodOptions)
	// router.HandleFunc("/device_authorization", granter.AuthorizationHandler).Methods(http.MethodPost, http.MethodOptions)

	return router, &granter
}