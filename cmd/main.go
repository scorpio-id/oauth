package main

import (
	"log"
	"net/http"

	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/transport"
)

// @title Swagger Example API
// @version 1.0
// @description This is a sample rk-demo server.
// @termsOfService http://swagger.io/terms/

// @securityDefinitions.basic BasicAuth

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
func main() {
	// parse local config
	cfg := config.NewConfig("internal/config/local.yml")

	// create a new mux router
	router, _ := transport.NewRouter(cfg)

	// start the server
	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
}

