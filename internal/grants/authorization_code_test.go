package grants

import (
	"testing"
	"github.com/jarcoal/httpmock"
)

// TestAuthorizationCodeGrant produces JWT via authorization code grant flow (link to rfc)
func TestAuthorizationCodeGrant(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// TODO - test authorization code grant flow ...
}