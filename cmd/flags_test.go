package main

import (
	"os"
	"testing"
)

func TestParseFlags_Help(t *testing.T) {
	// Sauvegarde de l'état initial
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Injection de --help
	os.Args = []string{"zandoli", "--help"}

	// Catch os.Exit via recover
	called := false
	exit = func(code int) {
		called = true
		panic("exit") // déclenché après usage
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected os.Exit(0), got none")
		}
		if !called {
			t.Fatal("Expected help flag to trigger exit")
		}
	}()

	parseFlags()
}

