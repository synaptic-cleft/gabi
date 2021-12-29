// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabikeys

import (
	"sort"
)

type (
	// SystemParameters holds the system parameters of the IRMA system.
	SystemParameters struct {
		BaseParameters
		DerivedParameters
	}

	// BaseParameters holds the base system parameters
	BaseParameters struct {
		LePrime uint
		Lh      uint
		Lm      uint
		Ln      uint
		Lstatzk uint
	}

	// DerivedParameters holds system parameters that can be derived from base
	// systemparameters (BaseParameters)
	DerivedParameters struct {
		Le            uint
		LeCommit      uint
		LmCommit      uint
		LRA           uint
		LsCommit      uint
		Lv            uint
		LvCommit      uint
		LvPrime       uint
		LvPrimeCommit uint
	}
)

// defaultBaseParameters holds per keylength the base parameters.
var (
	defaultBaseParameters = map[int]BaseParameters{
		1024: {
			LePrime: 120,
			Lh:      256,
			Lm:      256,
			Ln:      1024,
			Lstatzk: 80,
		},
		2048: {
			LePrime: 120,
			Lh:      256,
			Lm:      256,
			Ln:      2048,
			Lstatzk: 128,
		},
		4096: {
			LePrime: 120,
			Lh:      256,
			Lm:      512,
			Ln:      4096,
			Lstatzk: 128,
		},
	}

	// DefaultSystemParameters holds per keylength the default parameters as are
	// currently in use at the moment. This might (and probably will) change in the
	// future.
	DefaultSystemParameters = map[int]*SystemParameters{
		1024: {defaultBaseParameters[1024], MakeDerivedParameters(defaultBaseParameters[1024])},
		2048: {defaultBaseParameters[2048], MakeDerivedParameters(defaultBaseParameters[2048])},
		4096: {defaultBaseParameters[4096], MakeDerivedParameters(defaultBaseParameters[4096])},
	}

	// DefaultKeyLengths is a slice of integers holding the keylengths for which
	// system parameters are available.
	DefaultKeyLengths = getAvailableKeyLengths(DefaultSystemParameters)
)

// MakeDerivedParameters computes the derived system parameters
func MakeDerivedParameters(base BaseParameters) DerivedParameters {
	Lv := base.Ln + 2*base.Lstatzk + base.Lh + base.Lm + 4
	return DerivedParameters{
		Le:            base.Lstatzk + base.Lh + base.Lm + 5,
		LeCommit:      base.LePrime + base.Lstatzk + base.Lh,
		LmCommit:      base.Lm + base.Lstatzk + base.Lh,
		LRA:           base.Ln + base.Lstatzk,
		LsCommit:      base.Lm + base.Lstatzk + base.Lh + 1,
		Lv:            Lv,
		LvCommit:      Lv + base.Lstatzk + base.Lh,
		LvPrime:       base.Ln + base.Lstatzk,
		LvPrimeCommit: base.Ln + 2*base.Lstatzk + base.Lh,
	}
}

// getAvailableKeyLengths returns the keylengths for the provided map of system
// parameters.
func getAvailableKeyLengths(sysParamsMap map[int]*SystemParameters) []int {
	lengths := make([]int, 0, len(sysParamsMap))
	for k := range sysParamsMap {
		lengths = append(lengths, k)
	}
	sort.Ints(lengths)
	return lengths
}
