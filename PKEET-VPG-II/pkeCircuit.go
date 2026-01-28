package main

import (
	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards1 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type PKECricuit struct {
	V  frontend.Variable
	X  frontend.Variable
	S  frontend.Variable
	MX frontend.Variable
	MY frontend.Variable

	HX frontend.Variable `gnark:",public"`
	HY frontend.Variable `gnark:",public"`

	PKX frontend.Variable `gnark:",public"`
	PKY frontend.Variable `gnark:",public"`
	UX  frontend.Variable `gnark:",public"`
	UY  frontend.Variable `gnark:",public"`
	VX  frontend.Variable `gnark:",public"`
	VY  frontend.Variable `gnark:",public"`
	YX  frontend.Variable `gnark:",public"`
	YY  frontend.Variable `gnark:",public"`

	W  frontend.Variable `gnark:",public"`
	W1 frontend.Variable `gnark:",public"`
	W2 frontend.Variable `gnark:",public"`

	BX frontend.Variable `gnark:",public"`
	BY frontend.Variable `gnark:",public"`
}

func (circuit *PKECricuit) Define(api frontend.API) error {
	curve, err := twistededwards1.NewEdCurve(api, twistededwards2.BLS12_381)
	if err != nil {
		panic(err)
	}
	base := twistededwards1.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	PK := twistededwards1.Point{
		X: circuit.PKX,
		Y: circuit.PKY,
	}
	H := twistededwards1.Point{
		X: circuit.HX,
		Y: circuit.HY,
	}

	m_ := curve.ScalarMul(base, circuit.X)
	_U := curve.ScalarMul(base, circuit.V)
	_V := curve.ScalarMul(m_, circuit.V)
	_Y := curve.ScalarMul(PK, circuit.V)

	api.AssertIsEqual(m_.X, circuit.MX)
	api.AssertIsEqual(m_.Y, circuit.MY)
	api.AssertIsEqual(_U.X, circuit.UX)
	api.AssertIsEqual(_U.Y, circuit.UY)
	api.AssertIsEqual(_V.X, circuit.VX)
	api.AssertIsEqual(_V.Y, circuit.VY)
	api.AssertIsEqual(_Y.X, circuit.YX)
	api.AssertIsEqual(_Y.Y, circuit.YY)

	miMC, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	One := curve.ScalarMul(base, 1)
	miMC.Write(_U.X, _U.Y, _V.X, _V.Y, _Y.X, _Y.Y, One.X, One.Y)
	hOut := miMC.Sum()

	Two := curve.ScalarMul(base, 2)
	miMC.Write(Two.X, Two.Y)
	hOut1 := miMC.Sum()

	Three := curve.ScalarMul(base, 3)
	miMC.Write(Three.X, Three.Y)
	hOut2 := miMC.Sum()

	hBits := api.ToBinary(hOut, 256)
	hBits1 := api.ToBinary(hOut1, 256)
	hBits2 := api.ToBinary(hOut2, 256)

	vBits := api.ToBinary(circuit.V, 256)
	mxBits := api.ToBinary(circuit.MX, 256)
	myBits := api.ToBinary(circuit.MY, 256)

	wBits := make([]frontend.Variable, 256)
	wBits1 := make([]frontend.Variable, 256)
	wBits2 := make([]frontend.Variable, 256)

	for i := 0; i < 256; i++ {
		wBits[i] = api.Xor(hBits[i], vBits[i])
		wBits1[i] = api.Xor(hBits1[i], mxBits[i])
		wBits2[i] = api.Xor(hBits2[i], myBits[i])
	}

	wb := api.FromBinary(wBits...)
	api.AssertIsEqual(circuit.W, wb)
	wb1 := api.FromBinary(wBits1...)
	api.AssertIsEqual(circuit.W1, wb1)
	wb2 := api.FromBinary(wBits2...)
	api.AssertIsEqual(circuit.W2, wb2)

	ind2 := curve.ScalarMul(H, circuit.S)
	B_ := curve.Add(m_, ind2)
	api.AssertIsEqual(B_.X, circuit.BX)
	api.AssertIsEqual(B_.Y, circuit.BY)

	return nil

}
