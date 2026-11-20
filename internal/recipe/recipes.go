// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package recipe

// All returns the recipes that ship with the agent, one for each connector.
//
// The list is empty on purpose. A recipe needs a tool name, its arguments and
// its result shape from a vendor document, and no vendor document that was read
// gives the result shape of a read tool. README.md lists each connector with
// its verified tool and what is missing. Add a recipe in its own file, named
// after the connector, and add it here.
func All() []Recipe { return nil }

// Default returns the book of the shipped recipes.
func Default() (*Book, error) { return NewBook(All()...) }
