package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type ETP struct {
	v       *big.Int
	_V      bn254.G1Affine // _V = _M^v
	HR_, X_ bn254.G2Affine // X_ = HR_^v
}

func (etp *ETP) Test(etp1 *ETP) error {
	res, err := bn254.Pair([]bn254.G1Affine{etp._V}, []bn254.G2Affine{etp1.X_})
	if err != nil {
		panic(err)
	}
	res1, err := bn254.Pair([]bn254.G1Affine{etp1._V}, []bn254.G2Affine{etp.X_})
	if err != nil {
		panic(err)
	}
	if res.Equal(&res1) {
		return nil
	}
	return fmt.Errorf("not equal")
}
