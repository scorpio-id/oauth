package grants

import (
	"net/http"
)

const OIDC_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

// .well-known OpenID Configuration URL
// https://accounts.google.com/.well-known/openid-configuration

// JWKS Google API
// https://www.googleapis.com/oauth2/v3/certs

// OIDC Token Exchange Handler
// RFC8693: https://datatracker.ietf.org/doc/html/rfc8693
func (g *Granter) OpenIDConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// ensure proper grant type string is included in token exchange request
	grant := r.FormValue("grant_type")
	if grant != OIDC_GRANT_TYPE {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	subjectTokenType := r.FormValue("subject_token_type")
	if subjectTokenType == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO ensure that subjectTokenType is among configured trusted OIDC issuers.

	subjectJWT := r.FormValue("subject_token")
	if subjectJWT == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO verify subject JWT using trusted OIDC issuer in subjectTokenType.

	// TODO issue new signed JWT with "act" (actor) claim which includes original subject.

	// generate access JWT
	// accessToken, err := g.Issuer.IssueAccessToken(client, g.Issuer.Audience)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// content, err := json.Marshal(accessToken)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// w.Header().Set("Content-Type", "application/json")
	// w.Write(content)
}