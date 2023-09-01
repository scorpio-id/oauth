package pkg

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-jose/go-jose/v3"
)

const (
	RS256 = "RS256"
	SIG   = "sig"
)

// NewJSONWebKeySet provides a single-key set with a kid value
func NewJSONWebKeySet(public rsa.PublicKey, kid string) jose.JSONWebKeySet {
	key := jose.JSONWebKey{
		Key:       &public,
		KeyID:     kid,
		Algorithm: RS256,
		Use:       SIG,
	}

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{key},
	}
}

// JWKSHandler a matching HTTP endpoint for hosting jwks
func (s *SimpleIssuer) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	response, err := json.Marshal(s.Keys)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
