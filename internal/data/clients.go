package data

import "sync"

// ClientStore acts as a simple in-memory client_id datastore
type ClientStore struct {
	IDs []string
	mu  sync.RWMutex
}

func NewClientStore() ClientStore {
	return ClientStore{
		IDs: make([]string, 0),
	}
}

func (c *ClientStore) Create() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.IDs = append(c.IDs)
}

func (c *ClientStore) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, v := range c.IDs {
		if v == id {
			c.IDs = append(c.IDs[:i], c.IDs[i+1:]...)
			break
		}
	}
}

func (c *ClientStore) Contains(id string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range c.IDs {
		if v == id {
			return true
		}
	}

	return false
}
