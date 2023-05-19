package grants

import (
	"log"
	"net/http"
	"encoding/json"
)


const RESPONSE_TYPE = "code"
const REQUEST_TYPE = "authorization_code"

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