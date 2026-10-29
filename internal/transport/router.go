package transport

import (
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/scorpio-id/oauth/docs"
	"github.com/swaggo/http-swagger/v2"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/grants"
	"github.com/scorpio-id/oauth/internal/tls"
)

// NewRouter creates a new mux router with applied server, oauth, and device grant configurations
func NewRouter(cfg config.Config) (*mux.Router, *grants.Granter) {
	// create a granter
	name := cfg.Server.Host + ":" + cfg.Server.Port
	minutes, _ := time.ParseDuration("10m")
	granter, err := grants.NewGranter(cfg, minutes, 8, name+"/device")
	if err != nil {
		log.Fatal(err)
	}

	// create gorilla mux router
	router := mux.NewRouter()

	// adding swagger 
	router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("https://oauth.scorpio.ordinarycomputing.com:" + cfg.Server.Port + "/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods(http.MethodGet)

	// host oauth2 JWKS endpoint
	router.HandleFunc(cfg.OAuth.JWKS, granter.Issuer.JWKSHandler)

	// host grant endpoints
	router.HandleFunc("/token", granter.ClientCredentialsHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/authorize", granter.AuthorizationCodeHandler).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/jwt", granter.AuthorizationTokenHandler).Methods(http.MethodPost, http.MethodOptions)

	// check if TLS is enabled, if so create cert client and serialize x509 if on linux OS
	if runtime.GOOS == "linux" {
		content, err := granter.ClientStore.LoadWebPKCS12()
		if err != nil {
			log.Fatal(err)
		}

		// serialize PKCS12 for SSL
		err = tls.SerializePKCS12(content, "/etc/ssl/certs")
		if err != nil {
			log.Fatal(err)
		}
	}

	// create a subrouter for CORS-enabled UIs
	subr := router.PathPrefix("/ui").Subrouter()

	// config endpoint for console
	subr.HandleFunc("/config", cfg.ConfigHandler).Methods(http.MethodGet, http.MethodOptions)

	// metadata endpoint for console
	subr.HandleFunc("/metadata", granter.MetadataHandler).Methods(http.MethodGet, http.MethodOptions)

	// host registration endpoint
	subr.HandleFunc("/register", granter.RegistrationHandler).Methods(http.MethodPost, http.MethodOptions)

	// enable CORS 
	subr.Use(mux.CORSMethodMiddleware(subr))

	return router, granter
}

