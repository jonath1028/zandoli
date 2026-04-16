// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package sniffer

type Packet struct {
    Data []byte
}

type PacketSource interface {
    Start() error
    Stop()
    Packets() <-chan Packet
}
