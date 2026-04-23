package data

import (
	"sync"
	"crypto/rand"
	"crypto/rsa"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/oauth/internal/config"
)

// ClientStore acts as a simple in-memory client id datastore
type ClientStore struct {
	IDs     []ClientID   `json:"clients"`
	Persist Persistence
	mu      sync.RWMutex
}

// ClientID represents an OAuth Client Identifier (user or application, created via registration)
type ClientID struct {
	ID                    string            `json:"id"`
	Email                 string            `json:"email"`
	UserPrincipalName     string            `json:"user_principal_name"`
	ServicePrincipalName  string            `json:"service_principal_name"`
	CommonName            string            `json:"common_name"`
	SubjectAlternateNames []string          `json:"subject_alternate_names"`
	Authorizations        map[string]string `json:"authorizations"`
}

func NewClientStore(cfg config.Config) ClientStore {
	return ClientStore{
		IDs: make([]ClientID, 0),
		Persist: NewPersistenceClient(cfg),
	}
}

// FIXME ensure client added is unique
func (c *ClientStore) Add(id ClientID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.IDs = append(c.IDs, id)
}

func (c *ClientStore) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, v := range c.IDs {
		if v.ID == id {
			c.IDs = append(c.IDs[:i], c.IDs[i+1:]...)
			break
		}
	}
}

func (c *ClientStore) Contains(id string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range c.IDs {
		if v.ID == id {
			return true
		}
	}

	return false
}

func (store *ClientStore) LoadWebX509AndPrivateKey() (*rsa.PrivateKey, []byte, error) {
	private, err := store.LoadKeyPair()
	if err != nil {
		return nil, nil, err
	}

	cert, err := store.Persist.GetX509()
	if err != nil {
		return nil, nil, err
	}

	return private, cert.Raw, nil
}

// FIXME this should clearly load the key pair used by the granter to sign JWTs
func (store *ClientStore) LoadKeyPair() (*rsa.PrivateKey, error) {
	if !store.Persist.cfg.Persistence.Enabled {
		return rsa.GenerateKey(rand.Reader, store.Persist.cfg.OAuth.RSABits)
	}

	stored, err := store.Persist.GetRSAKeyPair()

	// case: key doesn't exist in persistence store
	if err == redis.Nil {
		// start by creating a RSA public/private key pair
		private, err := rsa.GenerateKey(rand.Reader, store.Persist.cfg.OAuth.RSABits)
		if err != nil {
			return nil, err
		}

		err = store.Persist.SetRSAKeyPair(private)
		if err != nil {
			return nil, err
		}

		return private, nil

	} else if err != nil {
		return nil, err
	}

	return stored, nil
}
