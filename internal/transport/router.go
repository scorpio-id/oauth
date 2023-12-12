package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/swaggo/http-swagger/v2"
	_ "github.com/scorpio-id/oauth/cmd/docs"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/grants"
	"github.com/scorpio-id/oauth/pkg/oauth2"
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
	issuer := oauth2.NewSimpleIssuer(private, name+cfg.OAuth.JWKS, cfg.OAuth.Audience, time.Now(), hour)

	// create a granter
	name = cfg.Server.Host + ":" + cfg.Server.Port
	minutes, _ := time.ParseDuration("10m")
	granter := grants.NewGranter(issuer, minutes, 8, name+"/device")

	// create gorilla mux router
	router := mux.NewRouter()

	// adding swagger 
	router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://localhost:" + cfg.Server.Port + "/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods(http.MethodGet)

	// host oauth2 JWKS endpoint
	router.HandleFunc(cfg.OAuth.JWKS, issuer.JWKSHandler)

	// only adding client credentials grant endpoint for now ...
	router.HandleFunc("/token", granter.ClientCredentialsHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/authorize", granter.AuthorizationCodeHandler).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/jwt", granter.AuthorizationTokenHandler).Methods(http.MethodPost, http.MethodOptions)

	return router, &granter
}

