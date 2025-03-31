package main

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"math/big"
)

// PKEETNP PKEET without (No) Pairing
// r, U=g^r, V=M^r, W=H(U,V,PK^r) ⊕ M||r
type PKEETNP struct {
	PK, M twistededwards.PointAffine

	r  *big.Int
	cp Ciphertext
}

func (pkeetnp *PKEETNP) GetCircuit() *PKENPCircuit {
	var Y twistededwards.PointAffine
	Y.ScalarMultiplication(&pkeetnp.PK, pkeetnp.r)

	rByte := BigIntToFixed32Bytes(pkeetnp.r)

	// declare the assignment
	assignment := PKENPCircuit{
		R:   new(big.Int).SetBytes(rByte[:]),
		MX:  pkeetnp.M.X,
		MY:  pkeetnp.M.Y,
		PKX: pkeetnp.PK.X,
		PKY: pkeetnp.PK.Y,
		UX:  pkeetnp.cp.U.X,
		UY:  pkeetnp.cp.U.Y,
		VX:  pkeetnp.cp.V.X,
		VY:  pkeetnp.cp.V.Y,
		YX:  Y.X,
		YY:  Y.Y,
		W:   pkeetnp.cp.W[0],
		W1:  pkeetnp.cp.W[1],
		W2:  pkeetnp.cp.W[2],
	}

	return &assignment
}

// Encryption
func (pkeetnp *PKEETNP) Enc() {
	curve := twistededwards.GetEdwardsCurve()
	mod := &curve.Order

	pk := pkeetnp.PK
	m := pkeetnp.M

	// U=g^r, V=M^r, Y=PK^r
	r, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var U, V, Y twistededwards.PointAffine
	U.ScalarMultiplication(&curve.Base, r)
	V.ScalarMultiplication(&m, r)
	Y.ScalarMultiplication(&pk, r)

	_ux := U.X.Bytes()
	_uy := U.Y.Bytes()
	_vx := V.X.Bytes()
	_vy := V.Y.Bytes()
	_yx := Y.X.Bytes()
	_yy := Y.Y.Bytes()
	pref := append(_ux[:], _uy[:]...)
	pref = append(pref, _vx[:]...)
	pref = append(pref, _vy[:]...)
	pref = append(pref, _yx[:]...)
	pref = append(pref, _yy[:]...)

	var One, Two, Three twistededwards.PointAffine

	// first hash block
	hFunc := hash.MIMC_BN254.New()
	One.ScalarMultiplication(&curve.Base, big.NewInt(1))
	onex := One.X.Bytes()
	oney := One.Y.Bytes()
	onexy := append(onex[:], oney[:]...)
	hFunc.Write(append(pref[:], onexy[:]...))
	hOut := hFunc.Sum(nil)

	// second hash block
	hFunc.Reset()
	Two.ScalarMultiplication(&curve.Base, big.NewInt(2))
	twox := Two.X.Bytes()
	twoy := Two.Y.Bytes()
	twoxy := append(twox[:], twoy[:]...)
	hFunc.Write(append(pref[:], twoxy...))
	hOut1 := hFunc.Sum(nil)

	// third hash block
	hFunc.Reset()
	Three.ScalarMultiplication(&curve.Base, big.NewInt(3))
	threex := Three.X.Bytes()
	threey := Three.Y.Bytes()
	threexy := append(threex[:], threey[:]...)
	hFunc.Write(append(pref[:], threexy...))
	hOut2 := hFunc.Sum(nil)

	rByte := BigIntToFixed32Bytes(r)
	mxByte := m.X.Bytes()
	myByte := m.Y.Bytes()

	var resXOR, resXOR1, resXOR2 [32]byte
	for i := 0; i < 32; i++ {
		resXOR[i] = hOut[i] ^ rByte[i]
		resXOR1[i] = hOut1[i] ^ mxByte[i]
		resXOR2[i] = hOut2[i] ^ myByte[i]
	}
	res := new(big.Int).SetBytes(resXOR[:])
	res1 := new(big.Int).SetBytes(resXOR1[:])
	res2 := new(big.Int).SetBytes(resXOR2[:])

	cp := Ciphertext{
		U: U,
		V: V,
		W: [3]big.Int{*res, *res1, *res2},
	}
	pkeetnp.cp = cp
	pkeetnp.r = r
}

// Dec call the Dec function define for Ciphertext
// then compare the result with the M in PKEETNP
func (pkeetnp *PKEETNP) Dec(sk *big.Int) (twistededwards.PointAffine, bool) {
	m, res := pkeetnp.cp.Dec(sk)
	if res && m.Equal(&pkeetnp.M) {
		return m, true
	}
	return m, false
}

type Ciphertext struct {
	U twistededwards.PointAffine
	V twistededwards.PointAffine
	W [3]big.Int
}

// Dec decrypt the ciphertext with the decryption secret key
func (cp *Ciphertext) Dec(sk *big.Int) (twistededwards.PointAffine, bool) {
	curve := twistededwards.GetEdwardsCurve()

	var Y twistededwards.PointAffine
	Y.ScalarMultiplication(&cp.U, sk)

	_ux := cp.U.X.Bytes()
	_uy := cp.U.Y.Bytes()
	_vx := cp.V.X.Bytes()
	_vy := cp.V.Y.Bytes()
	_yx := Y.X.Bytes()
	_yy := Y.Y.Bytes()
	pref := append(_ux[:], _uy[:]...)
	pref = append(pref, _vx[:]...)
	pref = append(pref, _vy[:]...)
	pref = append(pref, _yx[:]...)
	pref = append(pref, _yy[:]...)

	var One, Two, Three twistededwards.PointAffine

	// first hash block
	hFunc := hash.MIMC_BN254.New()
	One.ScalarMultiplication(&curve.Base, big.NewInt(1))
	onex := One.X.Bytes()
	oney := One.Y.Bytes()
	onexy := append(onex[:], oney[:]...)
	hFunc.Write(append(pref[:], onexy[:]...))
	hOut := hFunc.Sum(nil)

	// second hash block
	hFunc.Reset()
	Two.ScalarMultiplication(&curve.Base, big.NewInt(2))
	twox := Two.X.Bytes()
	twoy := Two.Y.Bytes()
	twoxy := append(twox[:], twoy[:]...)
	hFunc.Write(append(pref[:], twoxy...))
	hOut1 := hFunc.Sum(nil)

	// third hash block
	hFunc.Reset()
	Three.ScalarMultiplication(&curve.Base, big.NewInt(3))
	threex := Three.X.Bytes()
	threey := Three.Y.Bytes()
	threexy := append(threex[:], threey[:]...)
	hFunc.Write(append(pref[:], threexy...))
	hOut2 := hFunc.Sum(nil)

	//rByte := BigIntToFixed32Bytes(r)
	//mxByte := m.X.Bytes()
	//myByte := m.Y.Bytes()
	WByte := BigIntToFixed32Bytes(&cp.W[0])
	WByte1 := BigIntToFixed32Bytes(&cp.W[1])
	WByte2 := BigIntToFixed32Bytes(&cp.W[2])

	var rByte, mxByte, myByte [32]byte
	for i := 0; i < 32; i++ {
		rByte[i] = hOut[i] ^ WByte[i]
		mxByte[i] = hOut1[i] ^ WByte1[i]
		myByte[i] = hOut2[i] ^ WByte2[i]
	}

	r := new(big.Int).SetBytes(rByte[:])
	var m twistededwards.PointAffine
	m.X.SetBytes(mxByte[:])
	m.Y.SetBytes(myByte[:])

	if cp.U.Equal(new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, r)) && cp.V.Equal(new(twistededwards.PointAffine).ScalarMultiplication(&m, r)) {
		return m, true
	}
	return *new(twistededwards.PointAffine), false
}

// BigIntToFixed32Bytes
// Turn a fr.Element into [32]byte,
// fill 0 in the front if the length is insufficient
func BigIntToFixed32Bytes(n *big.Int) [32]byte {
	b := n.Bytes()
	var fixed [32]byte
	copy(fixed[32-len(b):], b)
	return fixed
}
