package pkg

import (
	"log"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

// JWT contains a sample access token minted by this issuer which expires in 2122
// JWKS is a snapshot of the matching, hosted endpoint with kid value
const (
	TESTJWT  = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI5NDVjNmU0LTZkN2UtNGFmYS1hZmI0LTlkMWUzYzlmZDE5NSIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaW1wb3J0YW50LXJlc291cmNlLXNlcnZlciJdLCJleHAiOjQ4MTg1OTQ0MjAsImlhdCI6MTY2NDk5NDQyMCwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS5pby9qd2tzIiwianRpIjoiMWYwNDY4ZGEtZGIzNC00MTY2LTk4ZDEtOWQ2ZTRiMzkwNzYzIiwibmJmIjoxNjY0OTk0MzY1LCJzdWIiOiJzbm93eS1zdGFyI2ExYTdmNDFiLWIxNWQtNDkzZi05MmQ0LTM5M2Y3MDUyYWQ4NSJ9.s0IRt6uOLhIeuLi7UdjItsZA-8EFuIOE2VQBNHApcrqAMPjjoEod2yawtAg41zjIJo8vHUoLDcw9TIs0R9ghKNq1Y1fEbzhxcE8N5oYgG-zcZcudsGaMxKdkLXF7qPKT1ue7xwmSssVJHSSer5iw_hRY4B8OlejCnycuIZbhUEYyZfvJ1E7x_VHDVFMbKdAoOrFkwNSt8My4-DBmjRu6F8MIFlfHvur3wV8GFoqRP3rJtrjHwsJoEBk6pK1x3OgiZ7EozL5ITRFak8ShtJo9Pq-BV7sE-s9lZz--ta_AKfOvrI-m-j451BvwqHIaTwCrp1yvFskqxQWjWauArh8WDw"
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

	EXPJWT  = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjUxMGIwNzI3LTRkMWEtNDNhNi1hZDcxLTM2ODllNjBiOWZjYiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJpbXBvcnRhbnQtcmVzb3VyY2Utc2VydmVyIiwiZXhwIjoxNjgyNzE4MDEyLCJpYXQiOjE2ODI3MTc4OTIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkuaW8vandrcyIsImp0aSI6ImY3ZGI4MTQyLWM2NDktNDUyZi04Mjc1LWMxZTc3YjVlM2U1YyIsIm5iZiI6MTY4MjcxNzg4MSwic3ViIjoiZGl2aW5lLWhhemUifQ.UkM4LwN7HhEiMRtRDXXILFPi5Woxew-1bZwcJEpp66OVX8m1gTM5CyrJlcGkJPtqRk_stf5rVqYFpmVQNofbeMfNwpixy9Z9iq1-Ka_qD8lo3aAky1QV2s5mOLi5qhGSZNCl4i7qx6QgtrDYgqgXgcNdmPYhyhjRAE7WeaomsD0B-280YP2XEqEwPAa1GJS-Dha40RtVAyTPBGErOqRu40DU24tEDi1XxIdtdzK46_4j6lYYFbLboq2FgZOJBt9RuuvwFkZN_T3tPNsfjMjcEDJCooENAMVYm8fbLd5jd8HMxeBvifQKYxkQyaMx6Uhls-wU0OGkMM_Avg9Em5DZgw"
	EXPJWKS = `{
				"keys": [
					{
						"use": "sig",
						"kty": "RSA",
						"kid": "510b0727-4d1a-43a6-ad71-3689e60b9fcb",
						"alg": "RS256",
						"n": "tmqNCn0EggqsgFDgmQRx595SweDMbq6zTQgg8JUuZSCZokwgPNfUkgHNipjE-JUiiA2kth_-AWpQ4PAD3VRH6ZOL8j6sONlNHJfDn7Nwh2tXXFCGS01GHDRCh_c5ZHiRhLz229YIUxxRbpOI5b9-j3QS6vsd-LC_iL8tNRaN8R2wZjI9elIvda_V3jw7OKN3n1A83Exd_GpmJ4599m8SJTNply9lfnPX8veOspiYRxAbkJmgG5uy-iBIs8X7RC-CKb2fUYEmG7bKNPxpdYysVSwGS716q4EAe8HFHfTR60-5y8uX1qQ7hJkaQJiC8H6mCMXdIh1COJnAmwfeoLhFuQ",
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

	claims, err := Verify(TESTJWT, []string{"https://identity.io/jwks"}, client)
	assert.Nil(t, err)

	log.Printf("issuer: %v, audience: %v, subject: %v", claims.Issuer, claims.Audience, claims.Subject)
}

// TestResourceServerExpiredJWT verification fails when given an expired access token
func TestResourceServerExpiredJWT(t *testing.T) {
	// TODO - implement ...
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// register mocked jwks endpoint
	httpmock.RegisterResponder("GET", "https://identity.io/jwks",
		httpmock.NewStringResponder(200, EXPJWKS))

	client := http.Client{}

	_, err := Verify(EXPJWT, []string{"https://identity.io/jwks"}, client)
	assert.NotNil(t, err)

	log.Printf("%v", err)
}

// TestResourceServerWrongJWKS verification fails when using a mismatched JWKS
func TestResourceServerWrongJWKS(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// register mocked jwks endpoint
	httpmock.RegisterResponder("GET", "https://identity.io/jwks",
		httpmock.NewStringResponder(200, EXPJWKS))

	client := http.Client{}

	_, err := Verify(TESTJWT, []string{"https://identity.io/jwks"}, client)
	assert.NotNil(t, err)

	log.Printf("%v", err)
}
