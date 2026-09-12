package main

import (
	cryptoRand "crypto/rand"
	"runtime/debug"
)

func readFullRandom(buf []byte) (int, error) {
	return cryptoRand.Read(buf)
}

// circlVersion reports the exact resolved github.com/cloudflare/circl module
// version (e.g. "v1.6.5"), read from the binary's own build info rather than
// hard-coded, so the provenance recorded in the generated vectors can never
// drift from what was actually linked in.
func circlVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/cloudflare/circl" {
			return dep.Version
		}
	}
	return "unknown"
}
