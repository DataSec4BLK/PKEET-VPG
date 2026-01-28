package main

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"testing"
)

func TestPKEETVPG(t *testing.T) {
	// 1. Setup
	// // zkSNARKs
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}
	spk, svk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// // Jubjub
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	hj := getRandomG()
	pkeCrs := &PKECRS{&curve.Base, hj}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(pkeCrs.gj, sk)
	supKey := &Key{sk, pk}

	// // bls12-381
	_, _, g1, g2 := bls12381.Generators()
	h := getRandomG1()
	H := getRandomG1() // variable public generator
	pokCrs := NewPoKCRS(&g1, h, &g2)
	crs := &CRS{ccs, spk, svk, pkeCrs, pokCrs}

	// 2. user setup
	order := bls12381.ID.ScalarField()
	x, _ := rand.Int(rand.Reader, mod)
	k, _ := rand.Int(rand.Reader, order)
	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(pokCrs.g, x), new(bls12381.G1Affine).ScalarMultiplication(pokCrs.h, k))
	user := &PKEETVPG{x, k, C}

	// 3. prove
	pvp, err := user.Proof(crs, supKey.pk, H)
	if err != nil {
		panic(err)
	}

	// 4. verify
	err = Verify(crs, pvp)
	if err != nil {
		panic(err)
	}
}

func BenchmarkPKEETVPG_Proof(b *testing.B) {
	// 1. Setup
	// // zkSNARKs
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}
	spk, svk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// // Jubjub
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	hj := getRandomG()
	pkeCrs := &PKECRS{&curve.Base, hj}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(pkeCrs.gj, sk)
	supKey := &Key{sk, pk}

	// // bls12-381
	_, _, g1, g2 := bls12381.Generators()
	h := getRandomG1()
	H := getRandomG1() // variable public generator
	pokCrs := NewPoKCRS(&g1, h, &g2)
	crs := &CRS{ccs, spk, svk, pkeCrs, pokCrs}

	// 2. user setup
	order := bls12381.ID.ScalarField()
	x, _ := rand.Int(rand.Reader, mod)
	k, _ := rand.Int(rand.Reader, order)
	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(pokCrs.g, x), new(bls12381.G1Affine).ScalarMultiplication(pokCrs.h, k))
	user := &PKEETVPG{x, k, C}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 3. prove
		_, _ = user.Proof(crs, supKey.pk, H)
	}
}

func BenchmarkPKEETVPG_Verify(b *testing.B) {
	// 1. Setup
	// // zkSNARKs
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}
	spk, svk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// // Jubjub
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	hj := getRandomG()
	pkeCrs := &PKECRS{&curve.Base, hj}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(pkeCrs.gj, sk)
	supKey := &Key{sk, pk}

	// // bls12-381
	_, _, g1, g2 := bls12381.Generators()
	h := getRandomG1()
	H := getRandomG1() // variable public generator
	pokCrs := NewPoKCRS(&g1, h, &g2)
	crs := &CRS{ccs, spk, svk, pkeCrs, pokCrs}

	// 2. user setup
	order := bls12381.ID.ScalarField()
	x, _ := rand.Int(rand.Reader, mod)
	k, _ := rand.Int(rand.Reader, order)
	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(pokCrs.g, x), new(bls12381.G1Affine).ScalarMultiplication(pokCrs.h, k))
	user := &PKEETVPG{x, k, C}

	// 3. prove
	pvp, err := user.Proof(crs, supKey.pk, H)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 4. verify
		_ = Verify(crs, pvp)
	}
}
