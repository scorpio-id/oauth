package oauth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	JWT    = "JWT"
	KID    = "kid"
	BEARER = "bearer"
)

type AccessToken struct {
	JWT       string `json:"access_token"`
	TokenType string `json:"token_type"`
	Expiry    int64  `json:"expires_in"`
}

func NewSigner(private *rsa.PrivateKey, kid string) (jose.Signer, error) {
	// create signing key
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       private,
	}

	// specify JSON Web Token
	opts := jose.SignerOptions{}
	opts.WithType(JWT)
	opts.WithHeader(KID, kid)

	return jose.NewSigner(key, &opts)
}

// Verify is used by resource servers to validate a jwt by retrieving a jwks from the 'iss' claim.
// the provided issuer string is considered a trusted issuer which we expect to see
// the client is any preferred http client
func Verify(token string, issuer string, client http.Client) (*jwt.Claims, error) {
	// start by decoding the jwt
	parsed, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	// we need to get the jwks endpoint from the 'iss' claim - as it stands, the claims are still untrusted
	unsafe := jwt.Claims{}
	err = parsed.UnsafeClaimsWithoutVerification(&unsafe)
	if err != nil {
		return nil, err
	}

	// check to see if issuer matches our expectation
	if unsafe.Issuer != issuer {
		return nil, errors.New("issuer is untrusted")
	}

	// let's now fetch the jwks, we assume that the 'iss' claim is a fqdn
	response, err := client.Get(issuer)
	if err != nil {
		return nil, err
	}

	jwks := jose.JSONWebKeySet{}
	err = json.NewDecoder(response.Body).Decode(&jwks)
	if err != nil {
		return nil, err
	}

	// we have the jwks, but we still need to find the correct public key. this is where we use the kid header
	// for now we only care about the first set of headers
	kid := parsed.Headers[0].KeyID

	// now see if there is a matching public key in the jwks
	key := jwks.Key(kid)

	claims := jwt.Claims{}
	err = parsed.Claims(key[0], &claims)
	if err != nil {
		return nil, err
	}

	// now we actually validate the claims ...
	err = claims.Validate(jwt.Expected{Issuer: issuer})
	if err != nil {
		return nil, err
	}

	return &claims, nil
}
