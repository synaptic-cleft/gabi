// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/rangeproof"
	"github.com/privacybydesign/gabi/revocation"
)

// Credential represents an Idemix credential.
type Credential struct {
	Signature            *CLSignature        `json:"signature"`
	Pk                   *gabikeys.PublicKey `json:"-"`
	Attributes           []*big.Int          `json:"attributes"`
	NonRevocationWitness *revocation.Witness `json:"nonrevWitness,omitempty"`

	nonrevCache chan *NonRevocationProofBuilder
}

// DisclosureProofBuilder is an object that holds the state for the protocol to
// produce a disclosure proof.
type DisclosureProofBuilder struct {
	randomizedSignature   *CLSignature
	eCommit, vCommit      *big.Int
	attrRandomizers       map[int]*big.Int
	z                     *big.Int
	disclosedAttributes   []int
	undisclosedAttributes []int
	pk                    *gabikeys.PublicKey
	attributes            []*big.Int
	nonrevBuilder         *NonRevocationProofBuilder

	rpStructures map[int][]*rangeproof.ProofStructure
	rpCommits    map[int][]*rangeproof.ProofCommit
}

type NonRevocationProofBuilder struct {
	pk          *gabikeys.PublicKey
	witness     *revocation.Witness
	commit      *revocation.ProofCommit
	commitments []*big.Int
	randomizer  *big.Int
	index       uint64
}

// UpdateCommit updates the builder to the latest accumulator contained in the specified (updated) witness.
func (b *NonRevocationProofBuilder) UpdateCommit(witness *revocation.Witness) error {
	if b == nil || b.commit == nil || len(b.commitments) < 5 {
		return errors.New("cannot update noninitialized NonRevocationProofBuilder")
	}
	if b.index >= witness.SignedAccumulator.Accumulator.Index {
		return nil
	}
	b.witness = witness
	b.commit.Update(b.commitments, witness)
	b.index = witness.SignedAccumulator.Accumulator.Index
	return nil
}

func (b *NonRevocationProofBuilder) Commit() ([]*big.Int, error) {
	if b.commitments == nil {
		var err error
		b.commitments, b.commit, err = revocation.NewProofCommit(b.pk, b.witness, b.randomizer)
		if err != nil {
			return nil, err
		}
	}
	return b.commitments, nil
}

func (b *NonRevocationProofBuilder) CreateProof(challenge *big.Int) *revocation.Proof {
	return b.commit.BuildProof(challenge)
}

// getUndisclosedAttributes computes, given a list of (indices of) disclosed
// attributes, a list of undisclosed attributes.
func getUndisclosedAttributes(disclosedAttributes []int, numAttributes int) []int {
	check := make([]bool, numAttributes)
	for _, v := range disclosedAttributes {
		check[v] = true
	}
	r := make([]int, 0, numAttributes)
	for i, v := range check {
		if !v {
			r = append(r, i)
		}
	}
	return r
}

// isUndisclosedAttribute computes, given the list of disclosed attributes, whether
// attribute stays hidden
func isUndisclosedAttribute(disclosedAttributes []int, attribute int) bool {
	for _, v := range disclosedAttributes {
		if v == attribute {
			return false
		}
	}
	return true
}

// CreateDisclosureProof creates a disclosure proof (ProofD) voor the provided
// indices of disclosed attributes.
func (ic *Credential) CreateDisclosureProof(
	disclosedAttributes []int,
	rangeStatements map[int][]*rangeproof.Statement,
	nonrev bool,
	context, nonce1 *big.Int,
) (*ProofD, error) {
	builder, err := ic.CreateDisclosureProofBuilder(disclosedAttributes, rangeStatements, nonrev)
	if err != nil {
		return nil, err
	}
	// context is used in Idemix but not in IRMA
	// IRMA uses a dedicated metadata attribute to contain the credential type
	// in IRMA we always set the context value to 1
	challenge, err := ProofBuilderList{builder}.Challenge(context, nonce1, false)
	if err != nil {
		return nil, err
	}
	return builder.CreateProof(challenge).(*ProofD), nil
}

// CreateDisclosureProofBuilder produces a DisclosureProofBuilder, an object to
// hold the state in the protocol for producing a disclosure proof that is
// linked to other proofs.
func (ic *Credential) CreateDisclosureProofBuilder(
	disclosedAttributes []int,
	rangeStatements map[int][]*rangeproof.Statement,
	nonrev bool,
) (*DisclosureProofBuilder, error) {
	d := &DisclosureProofBuilder{}
	d.z = big.NewInt(1)
	d.pk = ic.Pk
	var err error
	// in a nutshell, the core is just this line
	d.randomizedSignature, err = ic.Signature.Randomize(ic.Pk)
	if err != nil {
		return nil, err
	}
	// ZK for hiding e - first step: commitment for e
	d.eCommit, err = common.RandomBigInt(ic.Pk.Params.LeCommit)
	if err != nil {
		return nil, err
	}
	// ZK for hiding v - first step: commitment for v
	d.vCommit, err = common.RandomBigInt(ic.Pk.Params.LvCommit)
	if err != nil {
		return nil, err
	}

	// ZK for all hidden attributes - first step: random commitments for hidden attributes
	d.attrRandomizers = make(map[int]*big.Int)
	d.disclosedAttributes = disclosedAttributes
	d.undisclosedAttributes = getUndisclosedAttributes(disclosedAttributes, len(ic.Attributes))
	d.attributes = ic.Attributes
	for _, v := range d.undisclosedAttributes {
		d.attrRandomizers[v], err = common.RandomBigInt(ic.Pk.Params.LmCommit)
		if err != nil {
			return nil, err
		}
	}

	// ----- RANGE PROOF
	if rangeStatements != nil {
		d.rpStructures = make(map[int][]*rangeproof.ProofStructure)
		for index, statements := range rangeStatements {
			if !isUndisclosedAttribute(disclosedAttributes, index) {
				return nil, errors.New("Range statements on revealed attributes are not supported")
			}
			for _, statement := range statements {
				structure, err := statement.ProofStructure(index)
				if err != nil {
					return nil, err
				}
				d.rpStructures[index] = append(d.rpStructures[index], structure)
			}
		}
	}

	// ----- REVOCATION
	if !nonrev {
		return d, nil
	}
	if ic.NonRevocationWitness == nil {
		return nil, errors.New("cannot prove nonrevocation: credential has no witness")
	}

	revIdx, err := ic.NonrevIndex()
	if err != nil {
		return nil, err
	}
	d.nonrevBuilder, err = ic.nonrevConsumeBuilder()
	if err != nil {
		return nil, err
	}
	d.attrRandomizers[revIdx] = d.nonrevBuilder.randomizer

	return d, nil
}

func (ic *Credential) nonrevConsumeBuilder() (*NonRevocationProofBuilder, error) {
	// Using either the channel value or a new one ensures that our output is used at most once,
	// lest we totally break security: reusing randomizers in a second session makes it possible
	// for the verifier to compute our revocation witness e from the proofs
	select {
	case b := <-ic.nonrevCache:
		return b, b.UpdateCommit(ic.NonRevocationWitness)
	default:
		return ic.NonrevBuildProofBuilder()
	}
}

// NonrevPrepareCache ensures that the Credential's nonrevocation proof builder cache is
// usable, by creating one if it does not exist, or otherwise updating it to the latest accumulator
// contained in the credential's witness.
func (ic *Credential) NonrevPrepareCache() error {
	if ic.NonRevocationWitness == nil {
		return nil
	}
	if ic.nonrevCache == nil {
		ic.nonrevCache = make(chan *NonRevocationProofBuilder, 1)
	}
	var b *NonRevocationProofBuilder
	var err error
	select {
	case b = <-ic.nonrevCache:
		Logger.Trace("updating existing nonrevocation commitment")
		err = b.UpdateCommit(ic.NonRevocationWitness)
	default:
		Logger.Trace("instantiating new nonrevocation commitment")
		b, err = ic.NonrevBuildProofBuilder()
	}
	if err != nil {
		return err
	}

	// put it back in the channel, waiting to be consumed by nonrevConsumeBuilder()
	// if the channel has already been populated by another goroutine in the meantime we just discard
	select {
	case ic.nonrevCache <- b:
	default:
	}

	return err
}

// NonrevBuildProofBuilder builds and returns a new commited-to NonRevocationProofBuilder.
func (ic *Credential) NonrevBuildProofBuilder() (*NonRevocationProofBuilder, error) {
	if ic.NonRevocationWitness == nil {
		return nil, errors.New("credential has no nonrevocation witness")
	}
	b := &NonRevocationProofBuilder{
		pk:         ic.Pk,
		witness:    ic.NonRevocationWitness,
		index:      ic.NonRevocationWitness.SignedAccumulator.Accumulator.Index,
		randomizer: revocation.NewProofRandomizer(),
	}
	_, err := b.Commit()
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (ic *Credential) NonrevIndex() (int, error) {
	if ic.NonRevocationWitness == nil {
		return -1, errors.New("credential has no nonrevocation witness")
	}
	for idx, i := range ic.Attributes {
		if i.Cmp(ic.NonRevocationWitness.E) == 0 {
			return idx, nil
		}
	}
	return -1, errors.New("revocation attribute not included in credential")
}

func (d *DisclosureProofBuilder) MergeProofPCommitment(commitment *ProofPCommitment) {
	d.z.Mod(
		d.z.Mul(d.z, commitment.Pcommit),
		d.pk.N,
	)
}

// PublicKey returns the Idemix public key against which this disclosure proof will verify.
func (d *DisclosureProofBuilder) PublicKey() *gabikeys.PublicKey {
	return d.pk
}

// Commit commits to the first attribute (the secret) using the provided
// randomizer.
func (d *DisclosureProofBuilder) Commit(randomizers map[string]*big.Int) ([]*big.Int, error) {
	d.attrRandomizers[0] = randomizers["secretkey"]

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae, err := common.ModPow(d.randomizedSignature.A, d.eCommit, d.pk.N)
	if err != nil {
		return nil, err
	}
	Sv, err := common.ModPow(d.pk.S, d.vCommit, d.pk.N)
	if err != nil {
		return nil, err
	}
	d.z.Mul(d.z, Ae).Mul(d.z, Sv).Mod(d.z, d.pk.N)

	for _, v := range d.undisclosedAttributes {
		t, err := common.ModPow(d.pk.R[v], d.attrRandomizers[v], d.pk.N)
		if err != nil {
			return nil, err
		}
		d.z.Mul(d.z, t)
		d.z.Mod(d.z, d.pk.N)
	}

	list := []*big.Int{d.randomizedSignature.A, d.z}

	// ----- REVOCATION
	if d.nonrevBuilder != nil {
		l, err := d.nonrevBuilder.Commit()
		if err != nil {
			panic(err)
		}
		list = append(list, l...)
	}

	// ----- RANGE PROOF
	if d.rpStructures != nil {
		d.rpCommits = make(map[int][]*rangeproof.ProofCommit)
		// we need guaranteed order on index
		for index := 0; index < len(d.attributes); index++ {
			structures, ok := d.rpStructures[index]
			if !ok {
				continue
			}
			for _, s := range structures {
				contributions, commit, err := s.CommitmentsFromSecrets(d.pk, d.attributes[index], d.attrRandomizers[index])
				if err != nil {
					return nil, err
				}
				list = append(list, contributions...)
				d.rpCommits[index] = append(d.rpCommits[index], commit)
			}
		}
	}

	return list, nil
}

// CreateProof creates a (disclosure) proof with the provided challenge.
func (d *DisclosureProofBuilder) CreateProof(challenge *big.Int) Proof {
	// e in Idemix has a minimum value
	// e' = e - eMin
	// prover only proves knowledge of e', so less data (as in length needs to be transmitted)
	// the verifier uses the proof of knowledge of e' and combines it with eMin
	ePrime := new(big.Int).Sub(d.randomizedSignature.E, new(big.Int).Lsh(big.NewInt(1), d.pk.Params.Le-1))
	// note: the commitments for the following ZK proofs were already calculated in the CreateDisclosureProofBuilder method
	// this is normal Schnorr -> eResponse = eCommit + challenge*ePrime
	eResponse := new(big.Int).Mul(challenge, ePrime)
	eResponse.Add(d.eCommit, eResponse)
	// this is normal Schnorr -> vResponse = vCommit + challenge*vPrime
	vResponse := new(big.Int).Mul(challenge, d.randomizedSignature.V)
	vResponse.Add(d.vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range d.undisclosedAttributes {
		// exp is the value of a specific hidden attribute
		exp := d.attributes[v]
		if exp.BitLen() > int(d.pk.Params.Lm) {
			exp = common.IntHashSha256(exp.Bytes())
		}
		// this is normal Schnorr -> t = d.attrRandomizers[v] + challenge*exp
		t := new(big.Int).Mul(challenge, exp)
		// d.attrRandomizers[v] is the specific random commitment that was calculated for this hidden credential
		// in the CreateDisclosureProofBuilder method
		aResponses[v] = t.Add(d.attrRandomizers[v], t)
	}

	// the real disclosed values
	aDisclosed := make(map[int]*big.Int)
	for _, v := range d.disclosedAttributes {
		aDisclosed[v] = d.attributes[v]
	}

	// ----- REVOCATION
	var nonrevProof *revocation.Proof
	if d.nonrevBuilder != nil {
		nonrevProof = d.nonrevBuilder.CreateProof(challenge)
		delete(nonrevProof.Responses, "alpha") // reset from NonRevocationResponse during verification
	}

	// ----- RANGE PROOF
	var rangeProofs map[int][]*rangeproof.Proof
	if d.rpStructures != nil {
		rangeProofs = make(map[int][]*rangeproof.Proof)
		for index, structures := range d.rpStructures {
			for i, s := range structures {
				rangeProofs[index] = append(rangeProofs[index],
					s.BuildProof(d.rpCommits[index][i], challenge))
			}
		}
	}

	return &ProofD{
		C:                  challenge,
		A:                  d.randomizedSignature.A,
		EResponse:          eResponse,
		VResponse:          vResponse,
		AResponses:         aResponses,
		ADisclosed:         aDisclosed,
		NonRevocationProof: nonrevProof,
		RangeProofs:        rangeProofs,
	}
}

// TimestampRequestContributions returns the contributions of this disclosure proof
// to the message that is to be signed by the timestamp server:
// - A of the randomized CL-signature
// - Slice of bigints populated with the disclosed attributes and 0 for the undisclosed ones.
func (d *DisclosureProofBuilder) TimestampRequestContributions() (*big.Int, []*big.Int) {
	zero := big.NewInt(0)
	disclosed := make([]*big.Int, len(d.attributes))
	for i := 0; i < len(d.attributes); i++ {
		disclosed[i] = zero
	}
	for _, i := range d.disclosedAttributes {
		disclosed[i] = d.attributes[i]
	}
	return d.randomizedSignature.A, disclosed
}

// Generate secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm)
}
