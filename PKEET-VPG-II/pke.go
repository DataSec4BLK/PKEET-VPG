package main

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"math/big"
)

type PKECRS struct {
	gj, hj *twistededwards.PointAffine
}

type Key struct {
	sk *big.Int
	pk *twistededwards.PointAffine
}

type Ciphertext struct {
	U, V *twistededwards.PointAffine
	W    [3]big.Int
}

func Enc(crs *PKECRS, pk, m *twistededwards.PointAffine, v *big.Int) (*Ciphertext, error) {
	curve := twistededwards.GetEdwardsCurve()

	U := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, v)
	V := new(twistededwards.PointAffine).ScalarMultiplication(m, v)
	Y := new(twistededwards.PointAffine).ScalarMultiplication(pk, v)

	_ux := U.X.Bytes()
	_uy := U.Y.Bytes()
	_vx := V.X.Bytes()
	_vy := V.Y.Bytes()
	_yx := Y.X.Bytes()
	_yy := Y.Y.Bytes()
	arr := append(_ux[:], _uy[:]...)
	arr = append(arr, _vx[:]...)
	arr = append(arr, _vy[:]...)
	arr = append(arr, _yx[:]...)
	arr = append(arr, _yy[:]...)

	One := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, big.NewInt(1))
	Two := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, big.NewInt(2))
	Three := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, big.NewInt(3))

	hFunc := hash.MIMC_BLS12_381.New()

	onex := One.X.Bytes()
	oney := One.Y.Bytes()
	arr = append(arr, onex[:]...)
	arr = append(arr, oney[:]...)
	hFunc.Write(arr)
	ho1 := hFunc.Sum(nil)

	twox := Two.X.Bytes()
	twoy := Two.Y.Bytes()
	arr = append(arr, twox[:]...)
	arr = append(arr, twoy[:]...)
	hFunc.Reset()
	hFunc.Write(arr)
	ho2 := hFunc.Sum(nil)

	threex := Three.X.Bytes()
	threey := Three.Y.Bytes()
	arr = append(arr, threex[:]...)
	arr = append(arr, threey[:]...)
	hFunc.Reset()
	hFunc.Write(arr)
	ho3 := hFunc.Sum(nil)

	vByte := BigIntToFixed32Bytes(v)
	mxByte := m.X.Bytes()
	myByte := m.Y.Bytes()
	var resXOR, resXOR1, resXOR2 [32]byte
	for i := 0; i < 32; i++ {
		resXOR[i] = ho1[i] ^ vByte[i]
		resXOR1[i] = ho2[i] ^ mxByte[i]
		resXOR2[i] = ho3[i] ^ myByte[i]
	}
	res := new(big.Int).SetBytes(resXOR[:])
	res1 := new(big.Int).SetBytes(resXOR1[:])
	res2 := new(big.Int).SetBytes(resXOR2[:])

	return &Ciphertext{U, V, [3]big.Int{*res, *res1, *res2}}, nil
}

func Dec(crs *PKECRS, ct *Ciphertext, sk *big.Int) (*twistededwards.PointAffine, error) {
	Y := new(twistededwards.PointAffine).ScalarMultiplication(ct.U, sk)

	_ux := ct.U.X.Bytes()
	_uy := ct.U.Y.Bytes()
	_vx := ct.V.X.Bytes()
	_vy := ct.V.Y.Bytes()
	_yx := Y.X.Bytes()
	_yy := Y.Y.Bytes()
	arr := append(_ux[:], _uy[:]...)
	arr = append(arr, _vx[:]...)
	arr = append(arr, _vy[:]...)
	arr = append(arr, _yx[:]...)
	arr = append(arr, _yy[:]...)

	One := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, big.NewInt(1))
	Two := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, big.NewInt(2))
	Three := new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, big.NewInt(3))

	hFunc := hash.MIMC_BLS12_381.New()

	arr = append(arr, One.X.Marshal()...)
	arr = append(arr, One.Y.Marshal()...)
	hFunc.Write(arr)
	ho1 := hFunc.Sum(nil)

	arr = append(arr, Two.X.Marshal()...)
	arr = append(arr, Two.Y.Marshal()...)
	hFunc.Reset()
	hFunc.Write(arr)
	ho2 := hFunc.Sum(nil)

	arr = append(arr, Three.X.Marshal()...)
	arr = append(arr, Three.Y.Marshal()...)
	hFunc.Reset()
	hFunc.Write(arr)
	ho3 := hFunc.Sum(nil)

	WByte := BigIntToFixed32Bytes(&ct.W[0])
	WByte1 := BigIntToFixed32Bytes(&ct.W[1])
	WByte2 := BigIntToFixed32Bytes(&ct.W[2])

	var vByte, mxByte, myByte [32]byte
	for i := 0; i < 32; i++ {
		vByte[i] = ho1[i] ^ WByte[i]
		mxByte[i] = ho2[i] ^ WByte1[i]
		myByte[i] = ho3[i] ^ WByte2[i]
	}

	v := new(big.Int).SetBytes(vByte[:])
	var m twistededwards.PointAffine
	m.X.SetBytes(mxByte[:])
	m.Y.SetBytes(myByte[:])

	if ct.U.Equal(new(twistededwards.PointAffine).ScalarMultiplication(crs.gj, v)) && ct.V.Equal(new(twistededwards.PointAffine).ScalarMultiplication(&m, v)) {
		return &m, nil
	}
	return new(twistededwards.PointAffine), errors.New("decryption failed")
}

func BigIntToFixed32Bytes(n *big.Int) [32]byte {
	b := n.Bytes()
	var fixed [32]byte
	copy(fixed[32-len(b):], b)
	return fixed
}
