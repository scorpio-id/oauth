package oauth2

import (
	"crypto/rsa"
	"log"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

type SimpleIssuer struct {
	Name      string
	Audience  string
	Signer    jose.Signer
	Keys      jose.JSONWebKeySet
	NotBefore time.Time
	TokenTTL  time.Duration
}

// NewSimpleIssuer a jwt signer and matching jwks given a rsa key pair, iss name, aud name, start time, and jwt ttl
func NewSimpleIssuer(private *rsa.PrivateKey, name string, audience string, start time.Time, ttl time.Duration) SimpleIssuer {
	// generate uuid to serve as the kid
	kid := uuid.New().String()

	// create a JWT signer & matching JWKS from the generated pair
	signer, err := NewSigner(private, kid)
	if err != nil {
		log.Fatal(err)
	}

	return SimpleIssuer{
		Signer:    signer,
		Keys:      NewJSONWebKeySet(private.PublicKey, kid),
		NotBefore: start,
		Name:      name,
		Audience:  audience,
		TokenTTL:  ttl,
	}
}

// IssueAccessToken creates a signed jwt given a subject and audience for 'sub' and 'aud' claims
func (s *SimpleIssuer) IssueAccessToken(subject string, audience string) (*AccessToken, error) {
	builder := jwt.Signed(s.Signer)

	now := time.Now()
	later := time.Unix(now.Unix()+int64(s.TokenTTL.Seconds()), 0)

	claims := jwt.Claims{
		Issuer:    s.Name,
		Subject:   subject,
		Audience:  []string{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(later),
		NotBefore: jwt.NewNumericDate(s.NotBefore),
		ID:        uuid.New().String(),
	}

	accessJWT, err := builder.Claims(claims).CompactSerialize()
	if err != nil {
		return nil, err
	}

	return &AccessToken{
		JWT:       accessJWT,
		TokenType: BEARER,
		Expiry:    int64(s.TokenTTL.Seconds()),
	}, nil
}
