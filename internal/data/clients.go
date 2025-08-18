package data

import "sync"

// ClientStore acts as a simple in-memory client id datastore
type ClientStore struct {
	IDs []ClientID   `json:"clients"`
	mu  sync.RWMutex `json:"-"`
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

func NewClientStore() ClientStore {
	return ClientStore{
		IDs: make([]ClientID, 0),
	}
}

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
