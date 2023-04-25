package grants

import (
	"encoding/json"
	"log"
	"net/http"
)

// AccessTokenHandler as defined in https://www.rfc-editor.org/rfc/rfc8628#section-3.4
func (g *Granter) AccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// read form param values
	grant := r.FormValue("grant_type")
	client := r.FormValue("client_id")
	device := r.FormValue("device_code")

	if grant == "" || client == "" || device == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// as per spec, deny request if grant_type is incorrect
	if grant != TYPE {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// check to see if a trusted device exists
	if !g.IsTrustedDevice(device, client) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// device is trusted, generate access JWT
	// we're using a compound subject and sample resource server audience name
	accessToken, err := g.Issuer.IssueAccessToken(client+"#"+device, g.Issuer.Audience)
	if err != nil {
		log.Fatal(err)
	}

	content, err := json.Marshal(accessToken)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(content)
}
