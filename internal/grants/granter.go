package grants

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/oauth/internal/config"
	"github.com/scorpio-id/oauth/internal/data"
	"github.com/scorpio-id/oauth/internal/tls"
	"github.com/scorpio-id/oauth/pkg/oauth2"
)

const (
	RUNES = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	TYPE  = "urn:ietf:params:oauth:grant-type:device_code"
)

// Granter takes an issuer, datastores, code ttl configuration, and JWT
type Granter struct {
	Issuer             oauth2.SimpleIssuer
	ClientStore        data.ClientStore
	InteractionStore   data.InteractionStore
	TrustedDeviceStore data.TrustedDeviceStore
	CodeTTL            time.Duration
	VerificationURI    string
	Type               string
	UserCodeLength     int
}

func NewGranter(cfg config.Config, issuer oauth2.SimpleIssuer, ttl time.Duration, length int, uri string) Granter {
	return Granter{
		Issuer:           issuer,
		ClientStore:      data.NewClientStore(cfg),
		InteractionStore: data.NewInteractionStore(),
		CodeTTL:          ttl,
		VerificationURI:  uri,
		UserCodeLength:   length,
		Type:             TYPE,
	}
}

// TODO - implement separate types of interactions for different grants
// CreateInteraction records grant information provided to clients & users by client id
func (g *Granter) CreateInteraction(clientID string) data.Interaction {
	expires := time.Unix(time.Now().Unix()+int64(g.CodeTTL.Seconds()), 0)

	i := data.Interaction{
		ClientID:          clientID,
		AuthorizationCode: uuid.New().String(),
		DeviceCode:        g.generateDeviceCode(),
		UserCode:          g.generateUserCode(),
		Expires:           expires,
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

// AuthorizeClient checks for unexpired interaction given a clientID and authorization code
func (g *Granter) AuthorizeClient(client string, code string) error {
	i, err := g.InteractionStore.RetrieveAuthorization(client, code)
	if err != nil {
		return err
	}

	// delete one-time interaction
	g.InteractionStore.Delete(i.(data.Interaction))
	return nil
}

// IsTrustedDevice returns true iff there exists at least one trusted device with matching client_id and device_code
func (g *Granter) IsTrustedDevice(device string, client string) bool {
	return g.TrustedDeviceStore.Contains(device, client)
}

// FIXME this should load a PKCS12 and unpack the byte contents (see tls.go)
func (g *Granter) ObtainWebServerIdentity(cfg config.Config) (*rsa.PrivateKey, []byte, error) {
	if cfg.Persistence.Enabled {
		private, webcert, err := g.ClientStore.LoadWebX509AndPrivateKey()

		// persistence is enabled, but no web cert has been generated yet
		if err == redis.Nil {
			fmt.Println("persistence enabled, but no web private key, x509 found. generating ...")
			private, err = rsa.GenerateKey(crand.Reader, cfg.OAuth.RSABits)
			if err != nil {
				log.Fatal(err)
			}

			// TODO replace with tls.GetCert()
			webcert, err := tls.RetrieveTLSCertificate(cfg)
			if err != nil {
				return nil, nil, err
			}

			// FIXME save certs to persistence, move to function?
			content, err := x509.ParseCertificate(webcert)
			if err != nil {
				log.Fatal(err)
			}

			err = g.ClientStore.Persist.SetX509(content)
			if err != nil {
				log.Fatal(err)
			}

			err = g.ClientStore.Persist.SetRSAKeyPair(private)
			if err != nil {
				log.Fatal(err)
			}

		} else if err != nil {
			log.Fatal(err)
		}

		return private, webcert, err
	}

	// If persistence is turned off create new keys and certificates from scratch
	private, err := rsa.GenerateKey(crand.Reader, cfg.OAuth.RSABits)
	if err != nil {
		log.Fatal(err)
	}

	// TODO use tls.GetCert()
	webcert, err := tls.RetrieveTLSCertificate(cfg)
	if err != nil {
		return nil, nil, err
	}

	return private, webcert, err
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
