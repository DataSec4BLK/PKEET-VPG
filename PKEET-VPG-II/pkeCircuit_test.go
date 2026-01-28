package main

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"math/big"
	"testing"
)

func TestCircuit(t *testing.T) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	crs := &PKECRS{&curve.Base, getRandomG()}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, x)
	s, _ := rand.Int(rand.Reader, mod)
	B := new(twistededwards.PointAffine).Add(m, new(twistededwards.PointAffine).ScalarMultiplication(crs.hj, s))

	v, _ := rand.Int(rand.Reader, mod)
	Y := new(twistededwards.PointAffine).ScalarMultiplication(key.pk, v)

	ct, err := Enc(crs, key.pk, m, v)
	if err != nil {
		panic(err)
	}

	vBytes := BigIntToFixed32Bytes(v)
	xBytes := BigIntToFixed32Bytes(x)
	sBytes := BigIntToFixed32Bytes(s)

	assignment := &PKECricuit{
		V:   new(big.Int).SetBytes(vBytes[:]),
		X:   new(big.Int).SetBytes(xBytes[:]),
		S:   new(big.Int).SetBytes(sBytes[:]),
		MX:  m.X,
		MY:  m.Y,
		HX:  crs.hj.X,
		HY:  crs.hj.Y,
		PKX: key.pk.X,
		PKY: key.pk.Y,
		UX:  ct.U.X,
		UY:  ct.U.Y,
		VX:  ct.V.X,
		VY:  ct.V.Y,
		YX:  Y.X,
		YY:  Y.Y,
		W:   ct.W[0],
		W1:  ct.W[1],
		W2:  ct.W[2],
		BX:  B.X,
		BY:  B.Y,
	}
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}
	spk, svk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	secretWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, spk, secretWitness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, svk, publicWitness)
	if err != nil {
		panic(err)
	}
}

func BenchmarkCircuitSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var pCircuit PKECricuit
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
		if err != nil {
			panic(err)
		}
		_, _, err = groth16.Setup(ccs)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkCircuitProve(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	h := getRandomG()
	crs := &PKECRS{&curve.Base, h}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, x)
	s, err := rand.Int(rand.Reader, mod)
	B := new(twistededwards.PointAffine).Add(m, new(twistededwards.PointAffine).ScalarMultiplication(crs.hj, s))

	v, _ := rand.Int(rand.Reader, mod)
	Y := new(twistededwards.PointAffine).ScalarMultiplication(key.pk, v)

	ct, err := Enc(crs, key.pk, m, v)
	if err != nil {
		panic(err)
	}

	vBytes := BigIntToFixed32Bytes(v)
	xBytes := BigIntToFixed32Bytes(x)
	sBytes := BigIntToFixed32Bytes(s)

	assignment := &PKECricuit{
		V:   new(big.Int).SetBytes(vBytes[:]),
		X:   new(big.Int).SetBytes(xBytes[:]),
		S:   new(big.Int).SetBytes(sBytes[:]),
		MX:  m.X,
		MY:  m.Y,
		HX:  crs.hj.X,
		HY:  crs.hj.Y,
		PKX: key.pk.X,
		PKY: key.pk.Y,
		UX:  ct.U.X,
		UY:  ct.U.Y,
		VX:  ct.V.X,
		VY:  ct.V.Y,
		YX:  Y.X,
		YY:  Y.Y,
		W:   ct.W[0],
		W1:  ct.W[1],
		W2:  ct.W[2],
		BX:  B.X,
		BY:  B.Y,
	}
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}

	spk, _, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secretWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
		if err != nil {
			panic(err)
		}
		_, _ = groth16.Prove(ccs, spk, secretWitness)
	}
}

func BenchmarkCircuitVerify(b *testing.B) {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	h := getRandomG()
	crs := &PKECRS{&curve.Base, h}

	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	pk := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, sk)
	key := &Key{sk, pk}

	x, _ := rand.Int(rand.Reader, mod)
	m := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, x)
	s, err := rand.Int(rand.Reader, mod)
	B := new(twistededwards.PointAffine).Add(m, new(twistededwards.PointAffine).ScalarMultiplication(crs.hj, s))

	v, _ := rand.Int(rand.Reader, mod)
	Y := new(twistededwards.PointAffine).ScalarMultiplication(key.pk, v)

	ct, err := Enc(crs, key.pk, m, v)
	if err != nil {
		panic(err)
	}

	vBytes := BigIntToFixed32Bytes(v)
	xBytes := BigIntToFixed32Bytes(x)
	sBytes := BigIntToFixed32Bytes(s)

	assignment := &PKECricuit{
		V:   new(big.Int).SetBytes(vBytes[:]),
		X:   new(big.Int).SetBytes(xBytes[:]),
		S:   new(big.Int).SetBytes(sBytes[:]),
		MX:  m.X,
		MY:  m.Y,
		HX:  crs.hj.X,
		HY:  crs.hj.Y,
		PKX: key.pk.X,
		PKY: key.pk.Y,
		UX:  ct.U.X,
		UY:  ct.U.Y,
		VX:  ct.V.X,
		VY:  ct.V.Y,
		YX:  Y.X,
		YY:  Y.Y,
		W:   ct.W[0],
		W1:  ct.W[1],
		W2:  ct.W[2],
		BX:  B.X,
		BY:  B.Y,
	}
	var pCircuit PKECricuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &pCircuit)
	if err != nil {
		panic(err)
	}

	spk, svk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	secretWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, spk, secretWitness)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = groth16.Verify(proof, svk, publicWitness)
	}
}
