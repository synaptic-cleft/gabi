// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"
	"encoding/xml"
	"io/ioutil"
	"math/big"
	"os"
)

const (
	//XMLHeader can be a used as the XML header when writing keys in XML format.
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	// MaxNumAttributes holds the (current) maximum number of attributes.
	MaxNumAttributes = 6
	// DefaultEpochLength is the default epoch length for public keys.
	DefaultEpochLength = 432000
)

// PrivateKey represents an issuer's private key.
type PrivateKey struct {
	XMLName xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
	P       *big.Int `xml:"Elements>p"`
	Q       *big.Int `xml:"Elements>q"`
	PPrime  *big.Int `xml:"Elements>pPrime"`
	QPrime  *big.Int `xml:"Elements>qPrime"`
}

// NewPrivateKey creates a new issuer private key using the provided parameters.
func NewPrivateKey(p, q *big.Int) *PrivateKey {
	sk := PrivateKey{P: p, Q: q, PPrime: new(big.Int), QPrime: new(big.Int)}

	sk.PPrime.Sub(p, bigONE)
	sk.PPrime.Rsh(sk.PPrime, 1)

	sk.QPrime.Sub(q, bigONE)
	sk.QPrime.Rsh(sk.QPrime, 1)

	return &sk
}

// NewPrivateKeyFromXML creates a new issuer private key using the xml data
// provided.
func NewPrivateKeyFromXML(xmlInput string) (*PrivateKey, error) {
	privk := &PrivateKey{}
	err := xml.Unmarshal([]byte(xmlInput), privk)
	if err != nil {
		return nil, err
	}
	return privk, nil
}

// NewPrivateKeyFromFile create a new issuer private key from an xml file.
func NewPrivateKeyFromFile(filename string) (*PrivateKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	privk := &PrivateKey{}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(b, privk)
	if err != nil {
		return nil, err
	}
	return privk, nil
}

// WriteToFile writes the private key to an xml file.
func (privk *PrivateKey) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write the standard XML header
	_, err = f.Write([]byte(XMLHeader))
	if err != nil {
		return err
	}

	// And the actual xml body (with indentation)
	b, err := xml.MarshalIndent(privk, "", "   ")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

// xmlBases is an auxiliary struct to encode/decode the odd way bases are
// represented in the xml representation of public keys
type xmlBases struct {
	Num   int      `xml:"num,attr"`
	Base0 *big.Int `xml:"Base_0"`
	Base1 *big.Int `xml:"Base_1"`
	Base2 *big.Int `xml:"Base_2"`
	Base3 *big.Int `xml:"Base_3"`
	Base4 *big.Int `xml:"Base_4"`
	Base5 *big.Int `xml:"Base_5"`
}

// xmlFeatures is an auxiliary struct to make the XML encoding/decoding a bit
// easier while keeping the struct for PublicKey somewhat simple.
type xmlFeatures struct {
	Epoch struct {
		Length int `xml:"length,attr"`
	}
}

// Bases is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type Bases []*big.Int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (bl *Bases) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlBases

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}
	*bl = Bases{t.Base0, t.Base1, t.Base2, t.Base3, t.Base4, t.Base5}
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (bl *Bases) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	t := xmlBases{Num: len(*bl), Base0: (*bl)[0], Base1: (*bl)[1], Base2: (*bl)[2], Base3: (*bl)[3], Base4: (*bl)[4], Base5: (*bl)[5]}
	return e.EncodeElement(t, start)
}

// EpochLength is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type EpochLength int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (el *EpochLength) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlFeatures

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}
	*el = EpochLength(t.Epoch.Length)
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (el *EpochLength) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var t xmlFeatures
	t.Epoch.Length = int(*el)
	return e.EncodeElement(t, start)
}

// PublicKey represents an issuer's public key.
type PublicKey struct {
	XMLName     xml.Name          `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
	N           *big.Int          `xml:"Elements>n"` // Modulus n
	Z           *big.Int          `xml:"Elements>Z"` // Generator Z
	S           *big.Int          `xml:"Elements>S"` // Generator S
	R           Bases             `xml:"Elements>Bases"`
	EpochLength EpochLength       `xml:"Features"`
	Params      *SystemParameters `xml:"-"`
}

// NewPublicKey creates and returns a new public key based on the provided parameters.
func NewPublicKey(N, Z, S *big.Int, R []*big.Int) *PublicKey {
	return &PublicKey{
		N:           N,
		Z:           Z,
		S:           S,
		R:           R,
		EpochLength: DefaultEpochLength,
		Params:      &DefaultSystemParameters,
	}
}

// NewPublicKeyFromXML creates a new issuer public key using the xml data
// provided.
func NewPublicKeyFromXML(xmlInput string) (*PublicKey, error) {
	// TODO: this might fail in the future. The DefaultSystemParameters and the
	// public key might not match!
	pubk := &PublicKey{Params: &DefaultSystemParameters}
	err := xml.Unmarshal([]byte(xmlInput), pubk)
	if err != nil {
		return nil, err
	}
	return pubk, nil
}

// NewPublicKeyFromFile create a new issuer public key from an xml file.
func NewPublicKeyFromFile(filename string) (*PublicKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pubk := &PublicKey{}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(b, pubk)
	if err != nil {
		return nil, err
	}
	return pubk, nil
}

// WriteToFile writes the public key to an xml file.
func (pubk *PublicKey) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write the standard XML header
	_, err = f.Write([]byte(XMLHeader))
	if err != nil {
		return err
	}

	// And the actual xml body (with indentation)
	b, err := xml.MarshalIndent(pubk, "", "   ")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

// randomSafePrime produces a safe prime of the requested number of bits
func randomSafePrime(bits int) (*big.Int, error) {
	p2 := new(big.Int)
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		p2.Rsh(p, 1) // p2 = (p - 1)/2
		if p2.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// GenerateKeyPair generates a private/public keypair for an Issuer
func GenerateKeyPair(param *SystemParameters) (*PrivateKey, *PublicKey, error) {
	primeSize := param.Ln / 2

	// p and q need to be safe primes
	p, err := randomSafePrime(int(primeSize))
	if err != nil {
		return nil, nil, err
	}

	q, err := randomSafePrime(int(primeSize))
	if err != nil {
		return nil, nil, err
	}

	priv := &PrivateKey{P: p, Q: q, PPrime: new(big.Int), QPrime: new(big.Int)}

	// compute p' and q'
	priv.PPrime.Sub(priv.P, bigONE)
	priv.PPrime.Rsh(priv.PPrime, 1)

	priv.QPrime.Sub(priv.Q, bigONE)
	priv.QPrime.Rsh(priv.QPrime, 1)

	// compute n
	pubk := &PublicKey{Params: param, EpochLength: DefaultEpochLength}
	pubk.N = new(big.Int).Mul(priv.P, priv.Q)

	// Find an acceptable value for S; we follow lead of the Silvia code here:
	// Pick a random l_n value and check whether it is a quadratic residue modulo n

	var s *big.Int
	for {
		s, err = randomBigInt(param.Ln)
		if err != nil {
			return nil, nil, err
		}
		// check if S \elem Z_n
		if s.Cmp(pubk.N) > 0 {
			continue
		}
		if legendreSymbol(s, priv.P) == 1 && legendreSymbol(s, priv.Q) == 1 {
			break
		}
	}

	pubk.S = s

	// Derive Z from S
	var x *big.Int
	for {
		x, _ = randomBigInt(primeSize)
		if x.Cmp(bigTWO) > 0 && x.Cmp(pubk.N) < 0 {
			break
		}
	}

	// Compute Z = S^x mod n
	pubk.Z = new(big.Int).Exp(pubk.S, x, pubk.N)

	// Derive R_i for i = 0...MaxNumAttributes from S
	pubk.R = make([]*big.Int, MaxNumAttributes)
	for i := 0; i < MaxNumAttributes; i++ {
		pubk.R[i] = new(big.Int)

		var x *big.Int
		for {
			x, _ = randomBigInt(primeSize)
			if x.Cmp(bigTWO) > 0 && x.Cmp(pubk.N) < 0 {
				break
			}
		}
		// Compute R_i = S^x mod n
		pubk.R[i].Exp(pubk.S, x, pubk.N)
	}

	return priv, pubk, nil
}
