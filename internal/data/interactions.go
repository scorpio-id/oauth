package data

import (
	"errors"
	"sync"
	"time"
)

// Interaction stores information generated during grant flows
type Interaction struct {
	ClientID   string
	DeviceCode string
	UserCode   string
	Expires    time.Time
}

func (i *Interaction) IsExpired() bool {
	if time.Now().After(i.Expires) {
		return true
	}
	return false
}

type InteractionStore struct {
	Interactions []Interaction
	mu           sync.RWMutex
}

func NewInteractionStore() InteractionStore {
	return InteractionStore{
		Interactions: make([]Interaction, 0),
	}
}

func (s *InteractionStore) Add(i Interaction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Interactions = append(s.Interactions, i)
}

func (s *InteractionStore) Delete(i Interaction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for x, v := range s.Interactions {
		if v == i {
			s.Interactions = append(s.Interactions[:x], s.Interactions[x+1:]...)
			break
		}
	}
}

// Retrieve attempts to return an unexpired interaction given a user_code
func (s *InteractionStore) Retrieve(userCode string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range s.Interactions {
		if v.UserCode == userCode && !v.IsExpired() {
			return v, nil
		}
	}

	return nil, errors.New("no such interaction")
}
