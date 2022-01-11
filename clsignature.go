// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
)

// RepresentToPublicKey returns a representation of the given exponents in terms of the R bases
// from the public key. For example given exponents exps[1],...,exps[k] this function returns
//   R[1]^{exps[1]}*...*R[k]^{exps[k]} (mod N)
// with R and N coming from the public key. The exponents are hashed if their length
// exceeds the maximum message length from the public key.
func RepresentToPublicKey(pk *gabikeys.PublicKey, exps []*big.Int) (*big.Int, error) {
	return common.RepresentToBases(pk.R, exps, pk.N, pk.Params.Lm), nil
}

// CLSignature is a data structure for holding a Camenisch-Lysyanskaya signature.
type CLSignature struct {
	A         *big.Int
	E         *big.Int `json:"e"`
	V         *big.Int `json:"v"`
	KeyshareP *big.Int `json:"KeyshareP"` // R_0^{keysharesecret}, necessary for verification
}

// SignMessageBlock signs a message block (ms) and a commitment (U) using the
// Camenisch-Lysyanskaya signature scheme as used in the IdeMix system.
func signMessageBlockAndCommitment(sk *gabikeys.PrivateKey, pk *gabikeys.PublicKey, U *big.Int, ms []*big.Int) (
	*CLSignature, error) {
	// R is all R^a's added up
	R, err := RepresentToPublicKey(pk, ms)
	if err != nil {
		return nil, err
	}

	// v''
	vTilde, err := common.RandomBigInt(pk.Params.Lv - 1)
	if err != nil {
		return nil, err
	}
	twoLv := new(big.Int).Lsh(big.NewInt(1), pk.Params.Lv-1)
	v := new(big.Int).Add(twoLv, vTilde)

	// Q = inv( S^v * R * U) * Z
	numerator := new(big.Int).Exp(pk.S, v, pk.N)
	numerator.Mul(numerator, R).Mul(numerator, U).Mod(numerator, pk.N)

	invNumerator, ok := common.ModInverse(numerator, pk.N)
	if !ok {
		return nil, errors.New("failed to invert mod n")
	}
	Q := new(big.Int).Mul(pk.Z, invNumerator)
	Q.Mod(Q, pk.N)

	e, err := common.RandomPrimeInRange(rand.Reader, pk.Params.Le-1, pk.Params.LePrime-1)
	if err != nil {
		return nil, err
	}

	d, ok := common.ModInverse(e, sk.Order)
	if !ok {
		return nil, errors.New("failed to invert mod order")
	}
	A := new(big.Int).Exp(Q, d, pk.N)

	// TODO: this is probably open to side channel attacks, maybe use a
	// safe (raw) RSA signature?

	return &CLSignature{A: A, E: e, V: v}, nil
}

// SignMessageBlock signs a message block (ms) using the Camenisch-Lysyanskaya
// signature scheme as used in the IdeMix system.
func SignMessageBlock(sk *gabikeys.PrivateKey, pk *gabikeys.PublicKey, ms []*big.Int) (*CLSignature, error) {
	return signMessageBlockAndCommitment(sk, pk, big.NewInt(1), ms)
}

// Verify checks whether the signature is correct while being given a public key
// and the messages.
func (s *CLSignature) Verify(pk *gabikeys.PublicKey, ms []*big.Int) bool {
	// First check that e is in the range [2^{l_e - 1}, 2^{l_e - 1} + 2^{l_e_prime - 1}]
	start := new(big.Int).Lsh(big.NewInt(1), pk.Params.Le-1)
	end := new(big.Int).Lsh(big.NewInt(1), pk.Params.LePrime-1)
	end.Add(end, start)
	if s.E.Cmp(start) < 0 || s.E.Cmp(end) > 0 {
		return false
	}

	if !s.E.ProbablyPrime(80) {
		return false
	}

	// Q = A^e * R * S^v
	Ae := new(big.Int).Exp(s.A, s.E, pk.N)
	R, err := RepresentToPublicKey(pk, ms)
	if err != nil {
		return false
	}
	if s.KeyshareP != nil {
		R.Mul(R, s.KeyshareP)
	}
	Sv, err := common.ModPow(pk.S, s.V, pk.N)
	if err != nil {
		return false
	}
	Q := new(big.Int).Mul(Ae, R)
	Q.Mul(Q, Sv).Mod(Q, pk.N)

	// Signature verifies if Q == Z
	return pk.Z.Cmp(Q) == 0
}

// Randomize returns a randomized copy of the signature.
// Selective Disclosure step 1: randomize issuer's signature
func (s *CLSignature) Randomize(pk *gabikeys.PublicKey) (*CLSignature, error) {
	// LRA is the bit length ln (secret x element [0,n] and ln being the bit length of n) plus Lstatzk (added for security, 2^80 or 2^128 -> 80 or 128 bits)
	r, err := common.RandomBigInt(pk.Params.LRA)
	if err != nil {
		return nil, err
	}
	// new(big.Int).Exp(a,b,c) -> a is the base, b the exponent, c is the modulus
	APrime := new(big.Int).Mul(s.A, new(big.Int).Exp(pk.S, r, pk.N))
	// .Mod modifies the int pointer directly
	APrime.Mod(APrime, pk.N)
	t := new(big.Int).Mul(s.E, r)
	VPrime := new(big.Int).Sub(s.V, t)
	// Q: why a new pointer for e?
	// (A', e, v') is its own signature set and gets its own e (with its own pointer in memory)
	// it's not mandatory but good practice
	return &CLSignature{A: APrime, E: new(big.Int).Set(s.E), V: VPrime}, nil
}
