package main

import (
	"crypto/rand"
	"errors"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"math/big"
	"testing"
)

func TestCG(t *testing.T) {
	Gp := getRandomG()
	Hp := getRandomG()
	Gq := getRandomG1()
	Hq := getRandomG1()
	cg := NewCGCRS(bc, bx, bf, tau, Gp, Hp, Gq, Hq)

	// x, rp, rq
	x, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cg.bx)), nil))
	curve := twistededwards.GetEdwardsCurve()
	modP := &curve.Order
	modQ := bls12381.ID.ScalarField()
	rp, _ := rand.Int(rand.Reader, modP)
	rq, _ := rand.Int(rand.Reader, modQ)
	xp := XP{
		x:  x,
		rp: rp,
	}
	xq := XQ{
		x:  x,
		rq: rq,
	}
	cgps, err := cg.GenXP(&xp, &xq)
	if err != nil {
		t.Fatal(err)
	}
	err = cg.VerXPs(cgps)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSplit(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	modP := &curve.Order
	modQ := bls12381.ID.ScalarField()
	x, err := rand.Int(rand.Reader, modP)
	if err != nil {
		t.Fatal(err)
	}
	rp, _ := rand.Int(rand.Reader, modP)
	rq, _ := rand.Int(rand.Reader, modQ)

	Gp := getRandomG()
	Hp := getRandomG()
	Gq := getRandomG1()
	Hq := getRandomG1()
	cg := NewCGCRS(bc, bx, bf, tau, Gp, Hp, Gq, Hq)

	two128 := new(big.Int).Lsh(big.NewInt(1), uint(bx)) // 1 << 128
	// low = x mod 2^128
	lowX := new(big.Int).Mod(x, two128)
	lowRP := new(big.Int).Mod(rp, two128)
	lowRQ := new(big.Int).Mod(rq, two128)
	// high = x >> 128
	highX := new(big.Int).Rsh(x, uint(bx))
	highRP := new(big.Int).Rsh(rp, uint(bx))
	highRQ := new(big.Int).Rsh(rq, uint(bx))

	comP := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, x), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, rp))
	comQ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, x), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, rq))

	comPLow := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, lowX), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, lowRP))
	comPHigh := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, highX), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, highRP))

	comQLow := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, lowX), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, lowRQ))
	comQHigh := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, highX), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, highRQ))

	mergeP := new(twistededwards.PointAffine).Add(comPLow, new(twistededwards.PointAffine).ScalarMultiplication(comPHigh, two128))
	mergeQ := new(bls12381.G1Affine).Add(comQLow, new(bls12381.G1Affine).ScalarMultiplication(comQHigh, two128))

	if !comP.Equal(mergeP) || !comQ.Equal(mergeQ) {
		t.Fatal("comP and mergeQ not equal")
	}
}

func BenchmarkCGGen(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	modP := &curve.Order
	modQ := bls12381.ID.ScalarField()
	x, err := rand.Int(rand.Reader, modP)
	if err != nil {
		b.Fatal(err)
	}
	rp, _ := rand.Int(rand.Reader, modP)
	rq, _ := rand.Int(rand.Reader, modQ)

	Gp := getRandomG()
	Hp := getRandomG()
	Gq := getRandomG1()
	Hq := getRandomG1()
	cg := NewCGCRS(bc, bx, bf, tau, Gp, Hp, Gq, Hq)

	two128 := new(big.Int).Lsh(big.NewInt(1), uint(bx)) // 1 << 128
	// low = x mod 2^128
	lowX := new(big.Int).Mod(x, two128)
	lowRP := new(big.Int).Mod(rp, two128)
	lowRQ := new(big.Int).Mod(rq, two128)
	// high = x >> 128
	highX := new(big.Int).Rsh(x, uint(bx))
	highRP := new(big.Int).Rsh(rp, uint(bx))
	highRQ := new(big.Int).Rsh(rq, uint(bx))

	lowXp := &XP{lowX, lowRP}
	lowXq := &XQ{lowX, lowRQ}
	highXp := &XP{highX, highRP}
	highXq := &XQ{highX, highRQ}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cg.GenXP(lowXp, lowXq)
		_, _ = cg.GenXP(highXp, highXq)
	}
}

func BenchmarkCGVer(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	modP := &curve.Order
	modQ := bls12381.ID.ScalarField()
	x, err := rand.Int(rand.Reader, modP)
	if err != nil {
		b.Fatal(err)
	}
	rp, _ := rand.Int(rand.Reader, modP)
	rq, _ := rand.Int(rand.Reader, modQ)

	Gp := getRandomG()
	Hp := getRandomG()
	Gq := getRandomG1()
	Hq := getRandomG1()
	cg := NewCGCRS(bc, bx, bf, tau, Gp, Hp, Gq, Hq)

	two128 := new(big.Int).Lsh(big.NewInt(1), uint(bx)) // 1 << 128
	// low = x mod 2^128
	lowX := new(big.Int).Mod(x, two128)
	lowRP := new(big.Int).Mod(rp, two128)
	lowRQ := new(big.Int).Mod(rq, two128)
	// high = x >> 128
	highX := new(big.Int).Rsh(x, uint(bx))
	highRP := new(big.Int).Rsh(rp, uint(bx))
	highRQ := new(big.Int).Rsh(rq, uint(bx))

	lowXp := &XP{lowX, lowRP}
	lowXq := &XQ{lowX, lowRQ}
	highXp := &XP{highX, highRP}
	highXq := &XQ{highX, highRQ}

	comP := new(twistededwards.PointAffine).Add(new(twistededwards.PointAffine).ScalarMultiplication(cg.Gp, x), new(twistededwards.PointAffine).ScalarMultiplication(cg.Hp, rp))
	comQ := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(cg.Gq, x), new(bls12381.G1Affine).ScalarMultiplication(cg.Hq, rq))

	lowCGP, err := cg.GenXP(lowXp, lowXq)
	if err != nil {
		b.Fatal(err)
	}
	highCGP, err := cg.GenXP(highXp, highXq)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = cg.VerXPs(lowCGP)
		if err != nil {
			b.Fatal(err)
		}
		err = cg.VerXPs(highCGP)
		if err != nil {
			b.Fatal(err)
		}
		mergeP := new(twistededwards.PointAffine).Add(lowCGP[0].comP, new(twistededwards.PointAffine).ScalarMultiplication(highCGP[0].comP, two128))
		mergeQ := new(bls12381.G1Affine).Add(lowCGP[0].comQ, new(bls12381.G1Affine).ScalarMultiplication(highCGP[0].comQ, two128))
		if comP.Equal(mergeP) && comQ.Equal(mergeQ) {
			continue
		}
		b.Fatal(errors.New("not equal"))
	}
}
