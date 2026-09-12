// circl-helper is a one-shot CLI used only by
// scripts/interop/generate-circl-vectors.mts to cross-check this SDK's ML-DSA,
// ML-KEM-768 and X-Wing output against Cloudflare's CIRCL (an independent Go
// implementation). It is never run in CI and never built as part of the
// package: the vector generator invokes it once, locally, to produce the
// committed JSON fixtures under src/vectors/interop/, then CI only re-checks
// those committed bytes against the SDK's own code.
//
// Protocol: reads one JSON request object from stdin, writes one JSON
// response object to stdout. All key/ciphertext/signature material crosses
// the boundary as lowercase hex.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type mldsaRequest struct {
	Set       string `json:"set"`
	PkHex     string `json:"pkHex"`
	SkHex     string `json:"skHex"`
	MsgHex    string `json:"msgHex"`
	SdkSigHex string `json:"sdkSigHex"`
}

type mldsaResponse struct {
	Set                 string `json:"set"`
	CirclVerifiesSdkSig bool   `json:"circlVerifiesSdkSig"`
	CirclSigHex         string `json:"circlSigHex"`
	CirclVerifiesOwnSig bool   `json:"circlVerifiesOwnSig"`
}

type kemRequest struct {
	PkHex    string `json:"pkHex"`
	SkHex    string `json:"skHex"`
	SdkCtHex string `json:"sdkCtHex"`
	// Fixed encapsulation seed supplied by the caller, so CIRCL's own
	// encapsulate() is as reproducible as the SDK's — see EncapsulateTo's
	// seed parameter on both mlkem768.PublicKey and xwing.PublicKey.
	SeedHex string `json:"seedHex"`
}

type kemResponse struct {
	// Shared secret CIRCL recovers by decapsulating the SDK's ciphertext with
	// the SDK's secret key (cross-check direction 1: SDK encaps -> CIRCL decaps).
	CirclDecapsOfSdkCtSsHex string `json:"circlDecapsOfSdkCtSsHex"`
	// A fresh ciphertext/shared-secret pair CIRCL produces against the SDK's
	// public key (cross-check direction 2: CIRCL encaps -> SDK decaps, checked
	// on the Node side after this call returns).
	CirclCtHex string `json:"circlCtHex"`
	CirclSsHex string `json:"circlSsHex"`
}

type request struct {
	Mldsa []mldsaRequest `json:"mldsa"`
	Mlkem *kemRequest    `json:"mlkem"`
	Xwing *kemRequest    `json:"xwing"`
}

type response struct {
	CirclVersion string          `json:"circlVersion"`
	Mldsa        []mldsaResponse `json:"mldsa"`
	Mlkem        *kemResponse    `json:"mlkem,omitempty"`
	Xwing        *kemResponse    `json:"xwing,omitempty"`
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: invalid hex: %v\n", err)
		os.Exit(1)
	}
	return b
}

func toHex(b []byte) string { return hex.EncodeToString(b) }

func handleMldsa(req mldsaRequest) mldsaResponse {
	pk := mustHex(req.PkHex)
	sk := mustHex(req.SkHex)
	msg := mustHex(req.MsgHex)
	sdkSig := mustHex(req.SdkSigHex)

	var circlSig []byte
	var verifiesSdkSig, circlVerifiesOwnSig bool

	switch req.Set {
	case "44":
		var pub mldsa44.PublicKey
		var priv mldsa44.PrivateKey
		if err := pub.UnmarshalBinary(pk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa44 pk unmarshal: %v\n", err)
			os.Exit(1)
		}
		if err := priv.UnmarshalBinary(sk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa44 sk unmarshal: %v\n", err)
			os.Exit(1)
		}
		verifiesSdkSig = mldsa44.Verify(&pub, msg, nil, sdkSig)
		circlSig = make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&priv, msg, nil, false, circlSig); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa44 sign: %v\n", err)
			os.Exit(1)
		}
		circlVerifiesOwnSig = mldsa44.Verify(&pub, msg, nil, circlSig)
	case "65":
		var pub mldsa65.PublicKey
		var priv mldsa65.PrivateKey
		if err := pub.UnmarshalBinary(pk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa65 pk unmarshal: %v\n", err)
			os.Exit(1)
		}
		if err := priv.UnmarshalBinary(sk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa65 sk unmarshal: %v\n", err)
			os.Exit(1)
		}
		verifiesSdkSig = mldsa65.Verify(&pub, msg, nil, sdkSig)
		circlSig = make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&priv, msg, nil, false, circlSig); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa65 sign: %v\n", err)
			os.Exit(1)
		}
		circlVerifiesOwnSig = mldsa65.Verify(&pub, msg, nil, circlSig)
	case "87":
		var pub mldsa87.PublicKey
		var priv mldsa87.PrivateKey
		if err := pub.UnmarshalBinary(pk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa87 pk unmarshal: %v\n", err)
			os.Exit(1)
		}
		if err := priv.UnmarshalBinary(sk); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa87 sk unmarshal: %v\n", err)
			os.Exit(1)
		}
		verifiesSdkSig = mldsa87.Verify(&pub, msg, nil, sdkSig)
		circlSig = make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(&priv, msg, nil, false, circlSig); err != nil {
			fmt.Fprintf(os.Stderr, "circl-helper: mldsa87 sign: %v\n", err)
			os.Exit(1)
		}
		circlVerifiesOwnSig = mldsa87.Verify(&pub, msg, nil, circlSig)
	default:
		fmt.Fprintf(os.Stderr, "circl-helper: unknown ML-DSA set %q\n", req.Set)
		os.Exit(1)
	}

	return mldsaResponse{
		Set:                 req.Set,
		CirclVerifiesSdkSig: verifiesSdkSig,
		CirclSigHex:         toHex(circlSig),
		CirclVerifiesOwnSig: circlVerifiesOwnSig,
	}
}

func handleMlkem(req kemRequest) kemResponse {
	var pk mlkem768.PublicKey
	var sk mlkem768.PrivateKey
	if err := pk.Unpack(mustHex(req.PkHex)); err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: mlkem768 pk unpack: %v\n", err)
		os.Exit(1)
	}
	if err := sk.Unpack(mustHex(req.SkHex)); err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: mlkem768 sk unpack: %v\n", err)
		os.Exit(1)
	}

	// Direction 1: decapsulate the SDK's ciphertext with CIRCL.
	sdkCt := mustHex(req.SdkCtHex)
	ss1 := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss1, sdkCt)

	// Direction 2: CIRCL encapsulates against the same public key, using the
	// caller-supplied fixed seed so this is as reproducible as the SDK side.
	ct2 := make([]byte, mlkem768.CiphertextSize)
	ss2 := make([]byte, mlkem768.SharedKeySize)
	seed := mustHex(req.SeedHex)
	if len(seed) != mlkem768.EncapsulationSeedSize {
		fmt.Fprintf(
			os.Stderr,
			"circl-helper: mlkem768 encaps seed must be %d bytes, got %d\n",
			mlkem768.EncapsulationSeedSize, len(seed),
		)
		os.Exit(1)
	}
	pk.EncapsulateTo(ct2, ss2, seed)

	return kemResponse{
		CirclDecapsOfSdkCtSsHex: toHex(ss1),
		CirclCtHex:              toHex(ct2),
		CirclSsHex:              toHex(ss2),
	}
}

func handleXwing(req kemRequest) kemResponse {
	var pk xwing.PublicKey
	var sk xwing.PrivateKey
	if err := pk.Unpack(mustHex(req.PkHex)); err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: xwing pk unpack: %v\n", err)
		os.Exit(1)
	}
	sk.Unpack(mustHex(req.SkHex))

	sdkCt := mustHex(req.SdkCtHex)
	ss1 := make([]byte, xwing.SharedKeySize)
	sk.DecapsulateTo(ss1, sdkCt)

	ct2 := make([]byte, xwing.CiphertextSize)
	ss2 := make([]byte, xwing.SharedKeySize)
	seed := mustHex(req.SeedHex)
	if len(seed) != xwing.EncapsulationSeedSize {
		fmt.Fprintf(
			os.Stderr,
			"circl-helper: xwing encaps seed must be %d bytes, got %d\n",
			xwing.EncapsulationSeedSize, len(seed),
		)
		os.Exit(1)
	}
	pk.EncapsulateTo(ct2, ss2, seed)

	return kemResponse{
		CirclDecapsOfSdkCtSsHex: toHex(ss1),
		CirclCtHex:              toHex(ct2),
		CirclSsHex:              toHex(ss2),
	}
}

func main() {
	var req request
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: decode stdin: %v\n", err)
		os.Exit(1)
	}

	resp := response{CirclVersion: circlVersion()}
	for _, m := range req.Mldsa {
		resp.Mldsa = append(resp.Mldsa, handleMldsa(m))
	}
	if req.Mlkem != nil {
		r := handleMlkem(*req.Mlkem)
		resp.Mlkem = &r
	}
	if req.Xwing != nil {
		r := handleXwing(*req.Xwing)
		resp.Xwing = &r
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "circl-helper: encode stdout: %v\n", err)
		os.Exit(1)
	}
}
