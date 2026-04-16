// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package fusion

import (
	"net"
	"zandoli/pkg/model"
)

// MergeHosts is deprecated, use MergeResults instead
// This function is kept for backward compatibility but delegates to MergeResults
func MergeHosts(passive, active []*model.Host) []*model.Host {
	return MergeResults(passive, active)
}

func hostKey(ip net.IP, mac net.HardwareAddr) string {
	return ip.String() + "-" + mac.String()
}
