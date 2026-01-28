package main

import "C"
import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/big"
)

type PoKCRS struct {
	g, h *bls12381.G1Affine
	g_   *bls12381.G2Affine
}

type PoKProof struct {
	c, zx, zk, zt, zd, zw *big.Int
	C, X, D, H            *bls12381.G1Affine
	V_, T_                *bls12381.G2Affine
}

type PoKSec struct {
	x, k, t *big.Int
	m_      *bls12381.G2Affine
}

func NewPoKCRS(g, h *bls12381.G1Affine, g_ *bls12381.G2Affine) *PoKCRS {
	return &PoKCRS{g, h, g_}
}

func (crs *PoKCRS) GenPoKProof(sec *PoKSec, Cin, X, H *bls12381.G1Affine, V_ *bls12381.G2Affine) (*PoKProof, error) {
	order := bls12381.ID.ScalarField()
	d, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, fmt.Errorf("fail to generate random number: %w", err)
	}
	w := new(big.Int).ModInverse(sec.t, order)

	D := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, d), new(bls12381.G1Affine).ScalarMultiplication(crs.h, new(big.Int).Neg(sec.k)))
	T_ := new(bls12381.G2Affine).Add(new(bls12381.G2Affine).ScalarMultiplication(V_, w), new(bls12381.G2Affine).ScalarMultiplication(crs.g_, d))

	rx, _ := rand.Int(rand.Reader, order)
	rk, _ := rand.Int(rand.Reader, order)
	rt, _ := rand.Int(rand.Reader, order)
	rd, _ := rand.Int(rand.Reader, order)
	rw, _ := rand.Int(rand.Reader, order)

	A1 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, rx), new(bls12381.G1Affine).ScalarMultiplication(crs.h, rk))
	A2 := new(bls12381.G1Affine).ScalarMultiplication(H, rt)
	D1 := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, rd), new(bls12381.G1Affine).ScalarMultiplication(crs.h, new(big.Int).Neg(rk)))
	T1_ := new(bls12381.G2Affine).Add(new(bls12381.G2Affine).ScalarMultiplication(V_, rw), new(bls12381.G2Affine).ScalarMultiplication(crs.g_, rd))

	arr := append(crs.g.Marshal(), crs.h.Marshal()...)
	arr = append(arr, H.Marshal()...)
	arr = append(arr, crs.g_.Marshal()...)
	arr = append(arr, Cin.Marshal()...)
	arr = append(arr, V_.Marshal()...)
	arr = append(arr, X.Marshal()...)
	arr = append(arr, D.Marshal()...)
	arr = append(arr, T_.Marshal()...)
	arr = append(arr, A1.Marshal()...)
	arr = append(arr, A2.Marshal()...)
	arr = append(arr, D1.Marshal()...)
	arr = append(arr, T1_.Marshal()...)
	res := sha256.Sum256(arr)
	c := new(big.Int).SetBytes(res[:])

	zx := new(big.Int).Mod(new(big.Int).Add(rx, new(big.Int).Mul(c, sec.x)), order)
	zk := new(big.Int).Mod(new(big.Int).Add(rk, new(big.Int).Mul(c, sec.k)), order)
	zt := new(big.Int).Mod(new(big.Int).Add(rt, new(big.Int).Mul(c, sec.t)), order)
	zd := new(big.Int).Mod(new(big.Int).Add(rd, new(big.Int).Mul(c, d)), order)
	zw := new(big.Int).Mod(new(big.Int).Add(rw, new(big.Int).Mul(c, w)), order)

	return &PoKProof{c, zx, zk, zt, zd, zw, Cin, X, D, H, V_, T_}, nil
}

func (crs *PoKCRS) VerPoKProof(pkp *PoKProof) error {
	A1_ := new(bls12381.G1Affine).Sub(new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, pkp.zx), new(bls12381.G1Affine).ScalarMultiplication(crs.h, pkp.zk)), new(bls12381.G1Affine).ScalarMultiplication(pkp.C, pkp.c))
	A2_ := new(bls12381.G1Affine).Sub(new(bls12381.G1Affine).ScalarMultiplication(pkp.H, pkp.zt), new(bls12381.G1Affine).ScalarMultiplication(pkp.X, pkp.c))
	D1_ := new(bls12381.G1Affine).Sub(new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, pkp.zd), new(bls12381.G1Affine).ScalarMultiplication(crs.h, new(big.Int).Neg(pkp.zk))), new(bls12381.G1Affine).ScalarMultiplication(pkp.D, pkp.c))
	T1__ := new(bls12381.G2Affine).Sub(new(bls12381.G2Affine).Add(new(bls12381.G2Affine).ScalarMultiplication(pkp.V_, pkp.zw), new(bls12381.G2Affine).ScalarMultiplication(crs.g_, pkp.zd)), new(bls12381.G2Affine).ScalarMultiplication(pkp.T_, pkp.c))

	arr := append(crs.g.Marshal(), crs.h.Marshal()...)
	arr = append(arr, pkp.H.Marshal()...)
	arr = append(arr, crs.g_.Marshal()...)
	arr = append(arr, pkp.C.Marshal()...)
	arr = append(arr, pkp.V_.Marshal()...)
	arr = append(arr, pkp.X.Marshal()...)
	arr = append(arr, pkp.D.Marshal()...)
	arr = append(arr, pkp.T_.Marshal()...)
	arr = append(arr, A1_.Marshal()...)
	arr = append(arr, A2_.Marshal()...)
	arr = append(arr, D1_.Marshal()...)
	arr = append(arr, T1__.Marshal()...)
	res := sha256.Sum256(arr)
	c := new(big.Int).SetBytes(res[:])
	if c.Cmp(pkp.c) != 0 {
		return errors.New("pok proof is invalid, c mismatch")
	}

	res1, err := bls12381.Pair([]bls12381.G1Affine{*new(bls12381.G1Affine).Add(pkp.C, pkp.D)}, []bls12381.G2Affine{*crs.g_})
	if err != nil {
		panic(err)
	}
	res2, err := bls12381.Pair([]bls12381.G1Affine{*crs.g}, []bls12381.G2Affine{*pkp.T_})
	if err != nil {
		panic(err)
	}
	if !res1.Equal(&res2) {
		return errors.New("pok proof is invalid, pairing mismatch")
	}
	return nil
}
