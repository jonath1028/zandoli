// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"zandoli/pkg/model"
)

// FilterHostsNeedingSYN returns hosts with IP and no OSGuess
func FilterHostsNeedingSYN(hosts []*model.Host) []*model.Host {
	filtered := make([]*model.Host, 0, len(hosts))
	for _, h := range hosts {
		if h != nil && h.IP != nil && h.OSGuess == "" {
			filtered = append(filtered, h)
		}
	}
	return filtered
}
