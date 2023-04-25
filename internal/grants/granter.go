package grants

import (
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/scorpio-id/oauth/internal/data"
	"github.com/scorpio-id/oauth/pkg/oauth"
)

const (
	RUNES = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	TYPE  = "urn:ietf:params:oauth:grant-type:device_code"
)

// Granter takes an issuer, datastores, code ttl configuration, and JWT
type Granter struct {
	Issuer             oauth.SimpleIssuer
	ClientStore        data.ClientStore
	InteractionStore   data.InteractionStore
	TrustedDeviceStore data.TrustedDeviceStore
	CodeTTL            time.Duration
	VerificationURI    string
	Type               string
	UserCodeLength     int
}

func NewGranter(issuer oauth.SimpleIssuer, ttl time.Duration, length int, uri string) Granter {
	return Granter{
		Issuer:           issuer,
		ClientStore:      data.NewClientStore(),
		InteractionStore: data.NewInteractionStore(),
		CodeTTL:          ttl,
		VerificationURI:  uri,
		UserCodeLength:   length,
		Type:             TYPE,
	}
}

// CreateInteraction records grant information provided to clients & users by client id
func (g *Granter) CreateInteraction(clientID string) data.Interaction {
	expires := time.Unix(time.Now().Unix()+int64(g.CodeTTL.Seconds()), 0)

	i := data.Interaction{
		ClientID:   clientID,
		DeviceCode: g.generateDeviceCode(),
		UserCode:   g.generateUserCode(),
		Expires:    expires,
	}

	g.InteractionStore.Add(i)

	return i
}

// AuthorizeDevice checks for an unexpired interaction by user code and if exists, trusts device & deletes interaction
func (g *Granter) AuthorizeDevice(userCode string) error {
	// start by looking for a pre-existing interaction
	i, err := g.InteractionStore.Retrieve(userCode)
	if err != nil {
		return err
	}

	// interaction exists, clean it up
	interaction := i.(data.Interaction)
	defer g.InteractionStore.Delete(interaction)

	// create device based on original interaction data
	d := data.TrustedDevice{
		Code:  interaction.DeviceCode,
		Owner: interaction.ClientID,
	}

	// add device to trusted store
	g.TrustedDeviceStore.AddDevice(d)

	return nil
}

// IsTrustedDevice returns true iff there exists at least one trusted device with matching client_id and device_code
func (g *Granter) IsTrustedDevice(device string, client string) bool {
	return g.TrustedDeviceStore.Contains(device, client)
}

func (g *Granter) generateDeviceCode() string {
	// we're just going to do a UUID here for the sake of simplicity
	return uuid.New().String()
}

func (g *Granter) generateUserCode() string {
	// this code has to be simple enough for a human to interact with
	// randomize seed for user code generation
	rand.Seed(time.Now().UnixNano())
	runes := []rune(RUNES)

	code := make([]rune, g.UserCodeLength)
	for i := range code {
		code[i] = runes[rand.Intn(len(runes))]
	}
	return string(code)
}
