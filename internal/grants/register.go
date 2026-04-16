package grants

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/scorpio-id/oauth/internal/data"
)

// Client ID Registration Swagger Documentation
//
// @Summary Allows new users, applications, and administrators to create OAuth2 client IDs
// @Description Accepts client_id, email, user principal name, service principal name, common name, and subject alternate names as parameters in application/x-www-form-urlencoded HTTP request
// @Tags register
// @Accept application/x-www-form-urlencoded
// @Produce plain
// @Param client_id               query string true "client identifier"
// @Param email                   query string true "email address"
// @Param user_principal          query string true "kerberos user principal name"
// @Param service_principal       query string true "kerberos service principal name"
// @Param common_name             query string true "PKI common name"
// @Param subject_alternate_names query string true "PKI subject alternate name(s)"
//
// @Success	200 {string} string "OK"
// @Failure 400 {string} string "Bad Request - check your form params"
// @Failure 415 {string} string "Unsupported Media Type"
//
// @Router /register [post]
//
// RegistrationHandler allows new users, applications, and administrators to create OAuth2 client IDs
func (g *Granter) RegistrationHandler(w http.ResponseWriter, r *http.Request) {

	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// read mandatory form values
	client := r.FormValue("client_id")
	if client == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// read optional form values
	user := r.FormValue("user_principal")

	service := r.FormValue("service_principal")
	
	common := r.FormValue("common_name")

	// FIXME add support for multiple subject alternate names
	san := r.FormValue("subject_alternate_names")
	
	id := data.ClientID {
		ID: client,
		Email: email,
		UserPrincipalName: user,
		ServicePrincipalName: service,
		CommonName: common,
		SubjectAlternateNames: []string{san},
	}

	g.ClientStore.Add(id)

	w.WriteHeader(http.StatusOK)
}

func (g *Granter) MetadataHandler(w http.ResponseWriter, r *http.Request) {

	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	// return JSON representation of client id store
	w.Header().Set("Content-Type", "application/json")

	content, err := json.Marshal(g.ClientStore)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	w.Write(content)
}
