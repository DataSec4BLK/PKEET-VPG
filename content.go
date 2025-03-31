package main

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
)

// Content The input of the pkeetvpg scheme, with NIZK proof
type Content struct {
	k          *big.Int
	M, H, B    twistededwards.PointAffine
	_M, _H, _B bn254.G1Affine

	cint, zu, zk big.Int
}

// GetContent return Content with NIZK proof
func GetContent(uid *big.Int) *Content {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()

	// M=g^uid (twistededwards)
	// _M=G1^uid (bn254-G1)
	var M twistededwards.PointAffine
	M.ScalarMultiplication(&curve.Base, uid)

	var _M bn254.G1Affine
	_M.ScalarMultiplication(&G1, uid)

	// H = g^u (twistededwards)
	u, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	var H twistededwards.PointAffine
	H.ScalarMultiplication(&curve.Base, u)

	// _H = G1^u1 (bn254-G1)
	u1, _ := rand.Int(rand.Reader, &curve.Order)
	var _H bn254.G1Affine
	_H.ScalarMultiplication(&G1, u1)

	// B = M · H^k
	// _B = _M · _H^k
	k, err := rand.Int(rand.Reader, &curve.Order)
	if err != nil {
		panic(err)
	}
	var B twistededwards.PointAffine
	B.ScalarMultiplication(&H, k)
	B.Add(&M, &B)

	var _B bn254.G1Affine
	_B.ScalarMultiplication(&_H, k)
	_B.Add(&_M, &_B)

	cont := &Content{
		k:  k,
		M:  M,
		H:  H,
		B:  B,
		_M: _M,
		_H: _H,
		_B: _B,
	}
	cont.ProveSigma(uid)

	return cont
}

func (cont *Content) ProveSigma(uid *big.Int) {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()

	ru, _ := rand.Int(rand.Reader, &curve.Order)
	rk, _ := rand.Int(rand.Reader, &curve.Order)

	// BB = g^ru · h^rk
	index := twistededwards.NewPointAffine(fr.One(), fr.One())
	index.ScalarMultiplication(&curve.Base, ru)
	index1 := twistededwards.NewPointAffine(fr.One(), fr.One())
	index1.ScalarMultiplication(&cont.H, rk)
	BB := twistededwards.NewPointAffine(fr.One(), fr.One())
	BB.Add(&index, &index1)

	// _BB = G1^ru · _H^rk
	var _index bn254.G1Affine
	_index.ScalarMultiplication(&G1, ru)
	var _index1 bn254.G1Affine
	_index1.ScalarMultiplication(&cont._H, rk)
	var _BB bn254.G1Affine
	_BB.Add(&_index, &_index1)

	// B, BB, _B, _BB, g, h, G1, _H
	arr := append(cont.B.Marshal(), BB.Marshal()...)
	arr = append(arr, cont._B.Marshal()...)
	arr = append(arr, _BB.Marshal()...)
	arr = append(arr, curve.Base.Marshal()...)
	arr = append(arr, cont.H.Marshal()...)
	arr = append(arr, G1.Marshal()...)
	arr = append(arr, cont._H.Marshal()...)
	c := sha256.Sum256(arr)

	// zu = ru + c · u, zk = rk + c · k
	var zu, zk big.Int
	cint := new(big.Int).SetBytes(c[:])
	zu.Add(ru, new(big.Int).Mul(uid, cint))
	zk.Add(rk, new(big.Int).Mul(cont.k, cint))

	cont.cint = *cint
	cont.zu = zu
	cont.zk = zk
}

func (cont *Content) VerifySigma() bool {
	curve := twistededwards.GetEdwardsCurve()
	_, _, G1, _ := bn254.Generators()

	var B_B, ind, ind1, ind2, ind3 twistededwards.PointAffine
	ind.ScalarMultiplication(&curve.Base, &cont.zu)
	ind1.ScalarMultiplication(&cont.H, &cont.zk)
	ind2.ScalarMultiplication(&cont.B, &cont.cint)
	ind.Add(&ind, &ind1)
	ind3.Neg(&ind2)
	B_B.Add(&ind, &ind3)

	var _B_B, _ind, _ind1, _ind2, _ind3 bn254.G1Affine
	_ind.ScalarMultiplication(&G1, &cont.zu)
	_ind1.ScalarMultiplication(&cont._H, &cont.zk)
	_ind2.ScalarMultiplication(&cont._B, &cont.cint)
	_ind.Add(&_ind, &_ind1)
	_ind3.Neg(&_ind2)
	_B_B.Add(&_ind, &_ind3)

	arr1 := append(cont.B.Marshal(), B_B.Marshal()...)
	arr1 = append(arr1, cont._B.Marshal()...)
	arr1 = append(arr1, _B_B.Marshal()...)
	arr1 = append(arr1, curve.Base.Marshal()...)
	arr1 = append(arr1, cont.H.Marshal()...)
	arr1 = append(arr1, G1.Marshal()...)
	arr1 = append(arr1, cont._H.Marshal()...)
	c1 := sha256.Sum256(arr1)

	cint1 := new(big.Int).SetBytes(c1[:])

	if cont.cint.Cmp(cint1) == 0 {
		return true
	}
	return false
}
