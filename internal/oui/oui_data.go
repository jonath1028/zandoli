// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package oui

import (
	_ "embed"
)

// embeddedOUIData contains the OUI database embedded in the binary
//
//go:embed oui_embedded.txt
var embeddedOUIData string
