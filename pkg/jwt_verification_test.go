package pkg

import (
	"log"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/scorpio-id/oauth/pkg/oauth"
	"github.com/stretchr/testify/assert"
)

// JWT contains a sample access token minted by this issuer which expires in 2122
// JWKS is a snapshot of the matching, hosted endpoint with kid value
const (
	JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI5NDVjNmU0LTZkN2UtNGFmYS1hZmI0LTlkMWUzYzlmZDE5NSIsInR5cCI6IkpXVCJ9.eyJhdW" +
		"QiOlsiaW1wb3J0YW50LXJlc291cmNlLXNlcnZlciJdLCJleHAiOjQ4MTg1OTQ0MjAsImlhdCI6MTY2NDk5NDQyMCwiaXNzIjoiaHR0cHM" +
		"6Ly9pZGVudGl0eS5pby9qd2tzIiwianRpIjoiMWYwNDY4ZGEtZGIzNC00MTY2LTk4ZDEtOWQ2ZTRiMzkwNzYzIiwibmJmIjoxNjY0OTk0" +
		"MzY1LCJzdWIiOiJzbm93eS1zdGFyI2ExYTdmNDFiLWIxNWQtNDkzZi05MmQ0LTM5M2Y3MDUyYWQ4NSJ9.s0IRt6uOLhIeuLi7UdjItsZA" +
		"-8EFuIOE2VQBNHApcrqAMPjjoEod2yawtAg41zjIJo8vHUoLDcw9TIs0R9ghKNq1Y1fEbzhxcE8N5oYgG-zcZcudsGaMxKdkLXF7qPKT1" +
		"ue7xwmSssVJHSSer5iw_hRY4B8OlejCnycuIZbhUEYyZfvJ1E7x_VHDVFMbKdAoOrFkwNSt8My4-DBmjRu6F8MIFlfHvur3wV8GFoqRP3" +
		"rJtrjHwsJoEBk6pK1x3OgiZ7EozL5ITRFak8ShtJo9Pq-BV7sE-s9lZz--ta_AKfOvrI-m-j451BvwqHIaTwCrp1yvFskqxQWjWauArh8" +
		"WDw"
	JWKS = `{
    			"keys": [
        			{
            			"use": "sig",
            			"kty": "RSA",
            			"kid": "2945c6e4-6d7e-4afa-afb4-9d1e3c9fd195",
            			"alg": "RS256",
            			"n": "uJwfzRxlXARpVQlpxLbcxcZQRDUIe07TM5KZukRZzacZYnYGitL0MdXYuI4mfof0vx2qRVDQd0ngc7FkPLc_pTj3fgUNFYl8K8LJwKoUxbYUqMm6FGUGd_KOBx5UltYFR6LZJfevxyGbryVGo-hD1Nbt7OwOZXBGLFMw2EGyDijHcNSu0ucjXlZ7IOTQdVFoL9DMuRkmpuM1mpTa9hkNy3KOrQO1cjYme_BjpByFY5yegPZF90NsERaB81dNSk86Z9KMdj7WqaP6aiz7QkCAIka3F_2EjOV-09wnNVQLUj0RXcueQX7tyvZxJEzkph3FZmqFwAI1J5HHh1UBta5AGw",
            			"e": "AQAB"
        			}
    			]
			}`
)

// TestResourceServerJWTVerification checks if a resource server can verify a jwt minted by this issuer
func TestResourceServerJWTVerification(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// register mocked jwks endpoint
	httpmock.RegisterResponder("GET", "https://identity.io/jwks",
		httpmock.NewStringResponder(200, JWKS))

	client := http.Client{}

	claims, err := oauth.Verify(JWT, "https://identity.io/jwks", client)
	assert.Nil(t, err)

	log.Printf("issuer: %v, audience: %v, subject: %v", claims.Issuer, claims.Audience, claims.Subject)
}

// TestResourceServerExpiredJWT verification fails when given an expired access token
func TestResourceServerExpiredJWT(t *testing.T) {
	// TODO - implement ...
}
