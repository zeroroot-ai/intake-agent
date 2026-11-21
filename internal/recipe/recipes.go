// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package recipe

import "errors"

// All returns the recipes that ship with the agent, one for each connector.
//
// The list is empty on purpose. A recipe needs a tool name, its arguments and
// its result shape from a vendor document, and no vendor document that was read
// gives the result shape of a read tool. README.md lists each connector with
// its verified tool and what is missing. Add a recipe in its own file, named
// after the connector, and add it here.
func All() []Recipe { return nil }

// ErrNoRecipes is the refusal of Default when no recipe ships. An agent with no
// recipe reads no connector, so it must not start.
var ErrNoRecipes = errors.New("recipe: no recipe ships, so the agent has no connector to read")

// Default returns the book of the shipped recipes. It fails when no recipe
// ships.
func Default() (*Book, error) { return shipped(All()) }

func shipped(rs []Recipe) (*Book, error) {
	if len(rs) == 0 {
		return nil, ErrNoRecipes
	}
	return NewBook(rs...)
}
