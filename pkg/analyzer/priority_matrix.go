package analyzer

import (
	"fmt"
	"time"
)

// createCompositeKey creates a composite key for IP+VLAN mapping
func createCompositeKey(ip string, vlanID int) string {
	if vlanID > 0 {
		return fmt.Sprintf("%s+vlan%d", ip, vlanID)
	}
	return ip // For untagged traffic, use IP only
}

// SignalPriority represents the priority of a protocol signal
type SignalPriority struct {
	Protocol string // Protocol name (ARP, DHCP, mDNS, etc.)
	Priority int    // Priority score (higher = more reliable)
}

// PriorityMatrix defines priorities for different use cases
type PriorityMatrix struct {
	// IP↔MAC association: who can create/overwrite a link
	IPToMAC map[string]int

	// Role inference: signal confidence for determining client/server
	RoleInference map[string]int

	// Global confidence: overall signal score
	GlobalConfidence map[string]int
}

// GetIPToMACPriority returns the priority for IP↔MAC association
func (pm *PriorityMatrix) GetIPToMACPriority(protocol string) int {
	if priority, exists := pm.IPToMAC[protocol]; exists {
		return priority
	}
	return 0 // Default priority for unrecognized protocols
}

// GetRoleInferencePriority returns the priority for role inference
func (pm *PriorityMatrix) GetRoleInferencePriority(protocol string) int {
	if priority, exists := pm.RoleInference[protocol]; exists {
		return priority
	}
	return 20 // Default priority = "NO_SIGNALS"
}

// GetGlobalConfidence returns the global confidence of a protocol
func (pm *PriorityMatrix) GetGlobalConfidence(protocol string) int {
	if confidence, exists := pm.GlobalConfidence[protocol]; exists {
		return confidence
	}
	return 10 // Default low confidence
}

// ConflictResolver manages conflict resolution and the anti-flip window
type ConflictResolver struct {
	// Anti-flip window in seconds
	AntiFlipWindow time.Duration

	// IP↔MAC association history for detecting flips
	associationHistory map[string]*IPAssociationHistory
}

// IPAssociationHistory maintains the history of an IP↔MAC association
type IPAssociationHistory struct {
	IP           string
	MAC          string
	VLAN         int
	Protocol     string
	Priority     int
	LastSeen     time.Time
	FlipAttempts []FlipAttempt
}

// FlipAttempt represents an association change attempt
type FlipAttempt struct {
	OldMAC    string
	NewMAC    string
	Protocol  string
	Priority  int
	Timestamp time.Time
	Blocked   bool // true if blocked by the anti-flip window
}

// NewConflictResolver creates a new conflict resolver
func NewConflictResolver() *ConflictResolver {
	return &ConflictResolver{
		AntiFlipWindow:     90 * time.Second, // 90 seconds as specified
		associationHistory: make(map[string]*IPAssociationHistory),
	}
}

// CanAssociateIPToMAC checks if an IP↔MAC association can be created or modified.
// Returns (canAssociate, reasons)
func (cr *ConflictResolver) CanAssociateIPToMAC(ip, mac string, vlan int, protocol string, priority int) (bool, string) {
	compositeKey := createCompositeKey(ip, vlan)

	// Check if there is an existing association
	if history, exists := cr.associationHistory[compositeKey]; exists {
		// If it is the same MAC, allow (update)
		if history.MAC == mac {
			history.LastSeen = time.Now()
			history.Protocol = protocol
			history.Priority = priority
			return true, "same_mac_update"
		}

		// If it is a different MAC, check the anti-flip window
		if time.Since(history.LastSeen) < cr.AntiFlipWindow {
			// Within the anti-flip window
			if priority > history.Priority {
				// Higher priority: allow the flip
				history.FlipAttempts = append(history.FlipAttempts, FlipAttempt{
					OldMAC:    history.MAC,
					NewMAC:    mac,
					Protocol:  protocol,
					Priority:  priority,
					Timestamp: time.Now(),
					Blocked:   false,
				})
				return true, "priority_flip_allowed"
			} else {
				// Lower or equal priority: block
				history.FlipAttempts = append(history.FlipAttempts, FlipAttempt{
					OldMAC:    history.MAC,
					NewMAC:    mac,
					Protocol:  protocol,
					Priority:  priority,
					Timestamp: time.Now(),
					Blocked:   true,
				})
				return false, "flip_blocked_priority_too_low"
			}
		} else {
			// Outside anti-flip window: allow if priority >=
			if priority >= history.Priority {
				return true, "flip_allowed_outside_window"
			} else {
				return false, "flip_denied_priority_too_low"
			}
		}
	}

	// Nouvelle association : toujours autoriser
	cr.associationHistory[compositeKey] = &IPAssociationHistory{
		IP:           ip,
		MAC:          mac,
		VLAN:         vlan,
		Protocol:     protocol,
		Priority:     priority,
		LastSeen:     time.Now(),
		FlipAttempts: []FlipAttempt{},
	}
	return true, "new_association"
}

// GetFlipAttempts returns the flip attempts for an IP+VLAN
func (cr *ConflictResolver) GetFlipAttempts(ip string, vlan int) []FlipAttempt {
	compositeKey := createCompositeKey(ip, vlan)
	if history, exists := cr.associationHistory[compositeKey]; exists {
		return history.FlipAttempts
	}
	return []FlipAttempt{}
}

// CleanupHistory cleans up old association history
func (cr *ConflictResolver) CleanupHistory() {
	cutoff := time.Now().Add(-24 * time.Hour) // Garder 24h d'historique

	for key, history := range cr.associationHistory {
		if history.LastSeen.Before(cutoff) {
			delete(cr.associationHistory, key)
		}
	}
}
