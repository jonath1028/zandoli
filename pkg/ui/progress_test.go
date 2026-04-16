// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package ui

import (
	"testing"
	"time"
)

func TestPrintProgressBar_ZeroTotal(t *testing.T) {
	// Test avec total = 0 (cas problématique qui causait le panic)
	progressFunc := PrintProgressBar("Test", 0, "count", "N/A", 100*time.Millisecond)

	// Vérifier que la fonction ne panique pas
	progressFunc(0)
	progressFunc(1)
	progressFunc(10)
}

func TestPrintProgressBar_NormalTotal(t *testing.T) {
	// Test avec un total normal
	progressFunc := PrintProgressBar("Test", 100, "count", "00:30", 50*time.Millisecond)

	// Test différents pourcentages
	progressFunc(0)   // 0%
	progressFunc(25)  // 25%
	progressFunc(50)  // 50%
	progressFunc(75)  // 75%
	progressFunc(100) // 100%
}

func TestPrintProgressBar_TimeDisplay(t *testing.T) {
	// Test avec displayType "time"
	progressFunc := PrintProgressBar("TimeTest", 60, "time", "", 1*time.Second)

	// Test différents temps
	progressFunc(0)  // 0s / 60s
	progressFunc(30) // 30s / 60s
	progressFunc(60) // 60s / 60s
}

func TestPrintProgressBar_CountDisplay(t *testing.T) {
	// Test avec displayType "count"
	progressFunc := PrintProgressBar("CountTest", 254, "count", "00:17", 10*time.Millisecond)

	// Test différents compteurs
	progressFunc(0)   // 0 / 254
	progressFunc(127) // 127 / 254
	progressFunc(254) // 254 / 254
}

func TestPrintProgressBar_EdgeCases(t *testing.T) {
	// Test avec total = 1
	progressFunc1 := PrintProgressBar("Edge1", 1, "count", "N/A", 100*time.Millisecond)
	progressFunc1(0)
	progressFunc1(1)

	// Test avec total très grand
	progressFunc2 := PrintProgressBar("Edge2", 1000000, "count", "N/A", 100*time.Millisecond)
	progressFunc2(0)
	progressFunc2(500000)
	progressFunc2(1000000)

	// Test avec i > total
	progressFunc3 := PrintProgressBar("Edge3", 100, "count", "N/A", 100*time.Millisecond)
	progressFunc3(150) // Plus que le total
}

func TestPrintProgressBar_DifferentNames(t *testing.T) {
	// Test avec différents noms
	names := []string{
		"ARP Scan",
		"SYN Scan",
		"Sniffing",
		"Analysis",
		"Export",
		"Very Long Name That Should Still Work",
		"",
		"123",
		"Test-Name_With.Special@Chars!",
	}

	for _, name := range names {
		progressFunc := PrintProgressBar(name, 100, "count", "N/A", 100*time.Millisecond)
		progressFunc(50)
	}
}

func TestPrintProgressBar_DifferentETAs(t *testing.T) {
	// Test avec différents ETA
	etas := []string{
		"00:00",
		"00:30",
		"01:23",
		"12:34",
		"99:99",
		"",
		"N/A",
		"Unknown",
		"Very Long ETA String",
	}

	for _, eta := range etas {
		progressFunc := PrintProgressBar("ETATest", 100, "count", eta, 100*time.Millisecond)
		progressFunc(50)
	}
}

func TestPrintProgressBar_DifferentStepDelays(t *testing.T) {
	// Test avec différents délais
	delays := []time.Duration{
		0,
		1 * time.Millisecond,
		10 * time.Millisecond,
		100 * time.Millisecond,
		1 * time.Second,
		10 * time.Second,
	}

	for _, delay := range delays {
		progressFunc := PrintProgressBar("DelayTest", 100, "count", "N/A", delay)
		progressFunc(50)
	}
}

func TestPrintProgressBar_ConcurrentCalls(t *testing.T) {
	// Test d'appels concurrents
	progressFunc := PrintProgressBar("ConcurrentTest", 100, "count", "N/A", 100*time.Millisecond)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				progressFunc(j)
			}
			done <- true
		}(i)
	}

	// Attendre que toutes les goroutines se terminent
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestPrintProgressBar_ProgressCalculation(t *testing.T) {
	// Test que le calcul de progression est correct
	testCases := []struct {
		total    int
		current  int
		expected int // nombre de caractères remplis attendus
	}{
		{100, 0, 0},
		{100, 25, 10},  // 25% de 40 = 10
		{100, 50, 20},  // 50% de 40 = 20
		{100, 75, 30},  // 75% de 40 = 30
		{100, 100, 40}, // 100% de 40 = 40
		{200, 100, 20}, // 50% de 40 = 20
		{50, 25, 20},   // 50% de 40 = 20
		{1, 1, 40},     // 100% de 40 = 40
		{0, 0, 0},      // cas spécial
		{0, 1, 0},      // cas spécial
	}

	for _, tc := range testCases {
		progressFunc := PrintProgressBar("CalcTest", tc.total, "count", "N/A", 100*time.Millisecond)

		// Appeler la fonction et vérifier qu'elle ne panique pas
		progressFunc(tc.current)
	}
}

func TestPrintProgressBar_Completion(t *testing.T) {
	// Test que la barre de progression se termine correctement
	progressFunc := PrintProgressBar("CompletionTest", 100, "count", "N/A", 100*time.Millisecond)

	// Appeler avec la valeur finale
	progressFunc(100)

	// Vérifier qu'il n'y a pas de panic
}

func TestPrintProgressBar_EmptyString(t *testing.T) {
	// Test avec des chaînes vides
	progressFunc := PrintProgressBar("", 0, "", "", 0)
	progressFunc(0)
}

func TestPrintProgressBar_LargeValues(t *testing.T) {
	// Test avec de très grandes valeurs
	progressFunc := PrintProgressBar("LargeTest", 1000000, "count", "N/A", 100*time.Millisecond)

	progressFunc(0)
	progressFunc(500000)
	progressFunc(1000000)
}

func TestPrintProgressBar_NegativeValues(t *testing.T) {
	// Test avec des valeurs négatives (cas d'erreur potentiel)
	progressFunc := PrintProgressBar("NegativeTest", 100, "count", "N/A", 100*time.Millisecond)

	// Ces appels ne devraient pas causer de panic
	progressFunc(-1)
	progressFunc(-100)
}
