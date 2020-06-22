// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package main

import (
	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/server"
)

func main() {
	keyID := crypki.KeyID{}
	server.Main(&keyID)
}
