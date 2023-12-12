package grants

import (
	"encoding/json"
	"log"
	"net/http"
)

// ClientCredentialsHandler as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
func (g *Granter) ClientCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// read form values
	grant := r.FormValue("grant_type")
	if grant != "client_credentials" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	client := r.FormValue("client_id")
	if client == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO add authentication here ...

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
