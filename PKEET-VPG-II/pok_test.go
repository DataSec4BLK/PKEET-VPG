package main

import (
	"crypto/rand"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPoK(t *testing.T) {
	_, _, g1, g2 := bls12381.Generators()
	order := bls12381.ID.ScalarField()

	crs := NewPoKCRS(&g1, getRandomG1(), &g2)
	H := getRandomG1()

	x, err := rand.Int(rand.Reader, order)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := rand.Int(rand.Reader, order)
	nt, _ := rand.Int(rand.Reader, order)
	m_ := new(bls12381.G2Affine).ScalarMultiplication(crs.g_, x)
	sec := &PoKSec{x, k, nt, m_}

	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, x), new(bls12381.G1Affine).ScalarMultiplication(crs.h, k))
	V_ := new(bls12381.G2Affine).ScalarMultiplication(m_, nt)
	X := new(bls12381.G1Affine).ScalarMultiplication(H, nt)

	pkp, err := crs.GenPoKProof(sec, C, X, H, V_)
	if err != nil {
		t.Fatal(err)
	}
	res := crs.VerPoKProof(pkp)
	assert.Nil(t, res)
}

func BenchmarkPoKGen(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	order := bls12381.ID.ScalarField()

	crs := NewPoKCRS(&g1, getRandomG1(), &g2)
	H := getRandomG1()

	x, err := rand.Int(rand.Reader, order)
	if err != nil {
		b.Fatal(err)
	}
	k, _ := rand.Int(rand.Reader, order)
	nt, _ := rand.Int(rand.Reader, order)
	m_ := new(bls12381.G2Affine).ScalarMultiplication(crs.g_, x)
	sec := &PoKSec{x, k, nt, m_}

	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, x), new(bls12381.G1Affine).ScalarMultiplication(crs.h, k))
	V_ := new(bls12381.G2Affine).ScalarMultiplication(m_, nt)
	X := new(bls12381.G1Affine).ScalarMultiplication(H, nt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = crs.GenPoKProof(sec, C, X, H, V_)
	}
}

func BenchmarkPoKVer(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	order := bls12381.ID.ScalarField()

	crs := NewPoKCRS(&g1, getRandomG1(), &g2)
	H := getRandomG1()

	x, err := rand.Int(rand.Reader, order)
	if err != nil {
		b.Fatal(err)
	}
	k, _ := rand.Int(rand.Reader, order)
	nt, _ := rand.Int(rand.Reader, order)
	m_ := new(bls12381.G2Affine).ScalarMultiplication(crs.g_, x)
	sec := &PoKSec{x, k, nt, m_}

	C := new(bls12381.G1Affine).Add(new(bls12381.G1Affine).ScalarMultiplication(crs.g, x), new(bls12381.G1Affine).ScalarMultiplication(crs.h, k))
	V_ := new(bls12381.G2Affine).ScalarMultiplication(m_, nt)
	X := new(bls12381.G1Affine).ScalarMultiplication(H, nt)

	pkp, err := crs.GenPoKProof(sec, C, X, H, V_)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = crs.VerPoKProof(pkp)
	}
}

func BenchmarkPairing(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	for i := 0; i < b.N; i++ {
		_, err := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
		if err != nil {
			panic(err)
		}
	}
}
