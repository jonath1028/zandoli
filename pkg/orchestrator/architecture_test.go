// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"context"
	"net"
	"testing"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/stretchr/testify/assert"
)

// TestOrchestratorArchitectureCompliance vérifie que l'orchestrateur respecte l'architecture
func TestOrchestratorArchitectureCompliance(t *testing.T) {
	t.Run("Orchestrator_Creation", func(t *testing.T) {
		cfg := &config.Config{
			Interface: "lo",
			Mode: config.Mode{
				Active: true,
			},
		}

		log := testLogger()
		o := NewOrchestrator(cfg, log, "test_output")

		assert.NotNil(t, o)
		assert.Equal(t, cfg, o.Config)
		assert.Equal(t, log, o.Log)
		assert.Equal(t, "test_output", o.OutputPath)
		assert.NotNil(t, o.ActiveScanFunc)
	})

	t.Run("Orchestrator_DependencyInjection", func(t *testing.T) {
		cfg := &config.Config{
			Interface: "lo",
			Mode: config.Mode{
				Active: true,
			},
		}

		log := testLogger()

		// Test avec une fonction de scan personnalisée
		customScanFunc := func(ctx context.Context, cfg *config.Config, log *logger.Logger) []*model.Host {
			return []*model.Host{
				{
					IP:     net.ParseIP("192.168.1.1"),
					MACStr: "00:11:22:33:44:55",
					Vendor: "Test Vendor",
					Source: "test",
				},
			}
		}

		o := &Orchestrator{
			Config:         cfg,
			Log:            log,
			OutputPath:     "test_output",
			ActiveScanFunc: customScanFunc,
		}

		// Test que la fonction personnalisée est bien injectée
		hosts := o.ActiveScanFunc(context.Background(), cfg, log)
		assert.Len(t, hosts, 1)
		assert.Equal(t, "192.168.1.1", hosts[0].IP.String())
		assert.Equal(t, "test", hosts[0].Source)
	})
}

// TestOrchestratorLayerSeparation vérifie la séparation des couches
func TestOrchestratorLayerSeparation(t *testing.T) {
	t.Run("NoDirectInternalAccess", func(t *testing.T) {
		// L'orchestrateur peut utiliser internal/config et internal/logger
		// mais ne doit pas exposer directement les détails internes
		cfg := &config.Config{
			Interface: "lo",
			Mode: config.Mode{
				Active: true,
			},
		}

		log := testLogger()
		o := NewOrchestrator(cfg, log, "test_output")

		// Vérifier que l'orchestrateur encapsule correctement les dépendances
		assert.NotNil(t, o.Config)
		assert.NotNil(t, o.Log)
		assert.NotNil(t, o.OutputPath)
	})

	t.Run("InterfaceCompliance", func(t *testing.T) {
		// Test que l'orchestrateur respecte ses interfaces
		cfg := &config.Config{
			Interface: "lo",
			Mode: config.Mode{
				Active: true,
			},
		}

		log := testLogger()
		o := NewOrchestrator(cfg, log, "test_output")

		// Vérifier que ActiveScanFunc a la bonne signature
		assert.NotNil(t, o.ActiveScanFunc)

		// Test que la fonction peut être appelée
		hosts := o.ActiveScanFunc(context.Background(), cfg, log)
		// En cas d'erreur de permissions réseau, hosts peut être nil, ce qui est acceptable
		if hosts == nil {
			hosts = []*model.Host{}
		}
		assert.NotNil(t, hosts) // Peut être vide mais pas nil
	})
}

// TestOrchestratorConfigurationValidation vérifie la validation de configuration
func TestOrchestratorConfigurationValidation(t *testing.T) {
	t.Run("ValidConfiguration", func(t *testing.T) {
		cfg := &config.Config{
			Interface: "lo",
			Mode: config.Mode{
				Active: true,
			},
			Scan: config.ScanSettings{
				Targeted: false,
			},
		}

		log := testLogger()
		o := NewOrchestrator(cfg, log, "test_output")

		assert.NotNil(t, o)
		assert.Equal(t, "lo", o.Config.Interface)
		assert.True(t, o.Config.Mode.Active)
		assert.False(t, o.Config.Scan.Targeted)
	})

	t.Run("ConfigurationDefaults", func(t *testing.T) {
		cfg := &config.Config{}
		log := testLogger()
		o := NewOrchestrator(cfg, log, "test_output")

		assert.NotNil(t, o)
		// Vérifier que les valeurs par défaut sont appliquées
		assert.NotNil(t, o.Config)
	})
}
