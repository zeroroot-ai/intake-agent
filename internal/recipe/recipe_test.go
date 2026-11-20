// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package recipe

import "testing"

func valid() Recipe {
	return Recipe{
		Connector: "x", Class: Scanner, Source: "https://vendor.example/doc", Tool: "t",
		Args:  func(Marker) map[string]any { return nil },
		Parse: func([]byte) ([]Item, error) { return nil, nil },
	}
}

func TestValidate(t *testing.T) {
	mutations := map[string]func(*Recipe){
		"no connector":       func(r *Recipe) { r.Connector = "" },
		"class not in scope": func(r *Recipe) { r.Class = "ticket" },
		"no vendor source":   func(r *Recipe) { r.Source = "" },
		"http source":        func(r *Recipe) { r.Source = "http://vendor.example" },
		"no tool":            func(r *Recipe) { r.Tool = "" },
		"no args":            func(r *Recipe) { r.Args = nil },
		"no parse":           func(r *Recipe) { r.Parse = nil },
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("a valid recipe failed: %v", err)
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			r := valid()
			mut(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestClass(t *testing.T) {
	flaw := map[Class]bool{Scanner: true, Cloud: true, SIEM: false, EDR: false, Identity: false}
	for c, want := range flaw {
		if !c.InScope() {
			t.Errorf("%s must be in scope", c)
		}
		if c.IsFlaw() != want {
			t.Errorf("%s IsFlaw = %v, want %v", c, c.IsFlaw(), want)
		}
	}
	for _, c := range []Class{"observability", "ticket", "paging", "patch", "git-host", ""} {
		if c.InScope() {
			t.Errorf("%q must not be in scope", c)
		}
	}
}

func TestBook(t *testing.T) {
	a, b := valid(), valid()
	b.Connector = "y"
	book, err := NewBook(b, a)
	if err != nil {
		t.Fatalf("new book: %v", err)
	}
	if _, ok := book.For("y"); !ok {
		t.Fatal("y has a recipe")
	}
	if _, ok := book.For("z"); ok {
		t.Fatal("z has no recipe")
	}
	if _, err := NewBook(a, a); err == nil {
		t.Fatal("two recipes for one connector must fail")
	}
}

// TestShippedRecipesAreValid makes sure that each shipped recipe passes
// Validate, and so cites a vendor source.
func TestShippedRecipesAreValid(t *testing.T) {
	if _, err := Default(); err != nil {
		t.Fatalf("shipped recipes: %v", err)
	}
}
