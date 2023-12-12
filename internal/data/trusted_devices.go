package data

import (
	"sync"
)

type TrustedDevice struct {
	Code  string
	Owner string
}

// TrustedDeviceStore a sample in-memory store for trusted devices
type TrustedDeviceStore struct {
	Devices []TrustedDevice
	mu      sync.RWMutex
}

func NewTrustedDeviceStore() TrustedDeviceStore {
	return TrustedDeviceStore{
		Devices: make([]TrustedDevice, 0),
	}
}

func (s *TrustedDeviceStore) AddDevice(d TrustedDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// check if device already exists, and if so skip adding to avoid duplicates
	for _, device := range s.Devices {
		if device.Code == d.Code && device.Owner == d.Owner {
			return
		}
	}

	s.Devices = append(s.Devices, d)
}

// Contains is a little different - we need to know if there's a device with matching id / client_id
func (s *TrustedDeviceStore) Contains(deviceID string, clientID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, device := range s.Devices {
		if device.Code == deviceID && device.Owner == clientID {
			return true
		}
	}

	return false
}
