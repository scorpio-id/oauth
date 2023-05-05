package grants

import (
	"net/http"
	"github.com/google/uuid"
)

const RESPONSE_TYPE = "code"

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

	// create authorization code 
	// TODO - create & store an interaction with the client_id and generated authorization code
	code := uuid.New().String()

	// create redirect URL
	url := redirect + "?" + "code=" + code

	w.Header().Add("Location", url)
	w.WriteHeader(http.StatusFound)
}
