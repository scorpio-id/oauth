package grants

import (
	"log"
	"net/http"
	"encoding/json"
)


const RESPONSE_TYPE = "code"
const REQUEST_TYPE = "authorization_code"

// Authorization Code Grant Swagger Documentation
//
// @Summary Generates an authorization code as part of authorization code grant
// @Description Accepts response_type, client_id, and redirect_url parameters in application/x-www-form-urlencoded HTTP request
// @Tags grant
// @Accept application/x-www-form-urlencoded
// @Produce plain
// @Param response_type query string true "code"
// @Param client_id     query string true "client identifier"
// @Param redirect_uri  query string true "target redirect URI"
//
// @Success	300 {string} string "Found" 
// @Failure 400 {string} string "Bad Request - check your form params"
// @Failure 415 {string} string "Unsupported Media Type" 
//
// @Router /authorize [get]
//
// AuthorizationCodeHandler as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
func (g *Granter) AuthorizationCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// read form values
	response := r.FormValue("response_type")
	if response != RESPONSE_TYPE {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// read form values
	// TODO - check to ensure that the client_id actually exists! (post-registration)
	client := r.FormValue("client_id")
	if client == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	redirect := r.FormValue("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// create authorization code interaction
	i := g.CreateInteraction(client)

	// create redirect URL
	url := redirect + "?" + "code=" + i.AuthorizationCode

	w.Header().Add("Location", url)
	w.WriteHeader(http.StatusFound)
}

// Authorization Code Grant Swagger Documentation
//
// @Summary Generates an access JWT via Authorization Code Grant 
// @Description Accepts grant_type, code, redirect_uri, client_id in application/x-www-form-urlencoded HTTP request
// @Tags grant
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type    query string true "must be set to authorization_code"
// @Param code          query string true "vaild autolrization code generated via /authorize"
// @Param redirect_uri  query string true "matching redirect_uri provided in original /authorize request"
// @Param client_id     query string true "client identifier"
//
// @Success	200 {string} string "OK" 
// @Failure 400 {string} string "Bad Request"
// @Failure 415 {string} string "Unsupported Media Type" 
//
// @Router /jwt [post]
//
// AuthorizationTokenHandler as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
func (g *Granter) AuthorizationTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	grant := r.FormValue("grant_type")
	if grant != REQUEST_TYPE {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	redirect := r.FormValue("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO - check to ensure that the client_id actually exists! (post-registration)
	client := r.FormValue("client_id")
	if client == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err := g.AuthorizeClient(client, code)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// generate access JWT
	accessToken, err := g.Issuer.IssueAccessToken(client, g.Issuer.Audience)
	if err != nil {
		log.Fatal(err)
	}

	content, err := json.Marshal(accessToken)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(content)
	return
}
