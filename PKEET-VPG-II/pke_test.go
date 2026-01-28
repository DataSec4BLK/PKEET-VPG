package main

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPKEEncDec(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	h := getRandomG()
	crs := &PKECRS{&curve.Base, h}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, x)
	v, _ := rand.Int(rand.Reader, mod)

	ct, err := Enc(crs, key.pk, m, v)
	if err != nil {
		panic(err)
	}

	m_, err := Dec(crs, ct, key.sk)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, m, m_)
}

func BenchmarkPKEEnc(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	h := getRandomG()
	crs := &PKECRS{&curve.Base, h}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, x)
	v, _ := rand.Int(rand.Reader, mod)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Enc(crs, key.pk, m, v)
	}
}

func BenchmarkPKEDec(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	h := getRandomG()
	crs := &PKECRS{&curve.Base, h}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, x)
	v, _ := rand.Int(rand.Reader, mod)

	ct, err := Enc(crs, key.pk, m, v)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Dec(crs, ct, key.sk)
	}
}
