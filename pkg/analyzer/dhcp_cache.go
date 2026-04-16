// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"fmt"
	"sync"
	"time"
)

// DHCPCacheEntry represents an entry in the DHCP correlation cache
type DHCPCacheEntry struct {
	XID         uint32        // Transaction ID
	ClientMAC   string        // Client MAC
	ServerIP    string        // Server IP (if identified)
	ClientIP    string        // Client IP (if allocated)
	SubnetMask  string        // Subnet mask
	Router      []string      // List of routers
	DNS         []string      // List of DNS servers
	DomainName  string        // Nom de domaine
	LeaseTime   uint32        // Lease duration in seconds
	ServerID    string        // DHCP server identifier
	VendorClass string        // Classe de vendeur
	ClientID    string        // Client identifier (hex)
	FQDN        string        // Nom de domaine complet
	Routes      []DHCPRoute   // Routes statiques (option 121/249)
	Relay       DHCPRelayInfo // Informations de relais (option 82)
	FirstSeen   time.Time     // Premier timestamp
	LastSeen    time.Time     // Dernier timestamp
}

// DHCPRoute represents a DHCP static route
type DHCPRoute struct {
	Prefix  string // Network prefix (e.g., "10.1.2.0/24")
	NextHop string // Prochain saut (ex: "192.168.1.1")
}

// DHCPRelayInfo represents DHCP relay information
type DHCPRelayInfo struct {
	CircuitID string // Circuit ID (hex)
	RemoteID  string // Remote ID (hex)
}

// DHCPCache manages the DHCP correlation cache with TTL
type DHCPCache struct {
	mu      sync.RWMutex
	entries map[string]*DHCPCacheEntry // Key: "xid:mac"
	ttl     time.Duration
}

// NewDHCPCache creates a new DHCP cache
func NewDHCPCache() *DHCPCache {
	return &DHCPCache{
		entries: make(map[string]*DHCPCacheEntry),
		ttl:     5 * time.Minute, // 5-minute TTL as specified
	}
}

// GetOrCreate retrieves or creates an entry in the cache
func (c *DHCPCache) GetOrCreate(xid uint32, clientMAC string) *DHCPCacheEntry {
	key := c.makeKey(xid, clientMAC)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clean expired entries
	c.cleanup()

	entry, exists := c.entries[key]
	if !exists {
		entry = &DHCPCacheEntry{
			XID:       xid,
			ClientMAC: clientMAC,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		c.entries[key] = entry
	} else {
		entry.LastSeen = time.Now()
	}

	return entry
}

// Get retrieves an existing entry
func (c *DHCPCache) Get(xid uint32, clientMAC string) (*DHCPCacheEntry, bool) {
	key := c.makeKey(xid, clientMAC)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if exists && time.Since(entry.LastSeen) < c.ttl {
		return entry, true
	}

	return nil, false
}

// Update updates an existing entry
func (c *DHCPCache) Update(xid uint32, clientMAC string, updateFn func(*DHCPCacheEntry)) {
	key := c.makeKey(xid, clientMAC)

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[key]; exists {
		updateFn(entry)
		entry.LastSeen = time.Now()
	}
}

// makeKey creates a composite key for the cache
func (c *DHCPCache) makeKey(xid uint32, clientMAC string) string {
	return fmt.Sprintf("%d:%s", xid, clientMAC)
}

// cleanup removes expired entries
func (c *DHCPCache) cleanup() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.Sub(entry.LastSeen) > c.ttl {
			delete(c.entries, key)
		}
	}
}

// GetAllEntries returns all non-expired entries
func (c *DHCPCache) GetAllEntries() []*DHCPCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.cleanup()

	entries := make([]*DHCPCacheEntry, 0, len(c.entries))
	for _, entry := range c.entries {
		entries = append(entries, entry)
	}

	return entries
}
