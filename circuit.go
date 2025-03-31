package main

import (
	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards1 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type PKENPCircuit struct {
	R  frontend.Variable
	MX frontend.Variable
	MY frontend.Variable

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
}

func (circuit *PKENPCircuit) Define(api frontend.API) error {
	curve, err := twistededwards1.NewEdCurve(api, twistededwards2.BN254)
	if err != nil {
		panic(err)
	}
	base := twistededwards1.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	m := twistededwards1.Point{
		X: circuit.MX,
		Y: circuit.MY,
	}
	PK := twistededwards1.Point{
		X: circuit.PKX,
		Y: circuit.PKY,
	}
	Y := twistededwards1.Point{
		X: circuit.YX,
		Y: circuit.YY,
	}
	U := twistededwards1.Point{
		X: circuit.UX,
		Y: circuit.UY,
	}
	V := twistededwards1.Point{
		X: circuit.VX,
		Y: circuit.VY,
	}

	_U := curve.ScalarMul(base, circuit.R)
	_V := curve.ScalarMul(m, circuit.R)
	_Y := curve.ScalarMul(PK, circuit.R)

	api.AssertIsEqual(_U.X, U.X)
	api.AssertIsEqual(_U.Y, U.Y)
	api.AssertIsEqual(_V.X, V.X)
	api.AssertIsEqual(_V.X, V.X)
	api.AssertIsEqual(_Y.X, Y.X)
	api.AssertIsEqual(_Y.X, Y.X)

	miMC, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	One := curve.ScalarMul(base, 1)
	miMC.Write(U.X, U.Y, V.X, V.Y, _Y.X, _Y.Y, One.X, One.Y)
	hOut := miMC.Sum()

	miMC.Reset()
	Two := curve.ScalarMul(base, 2)
	miMC.Write(U.X, U.Y, V.X, V.Y, _Y.X, _Y.Y, Two.X, Two.Y)
	hOut1 := miMC.Sum()

	miMC.Reset()
	Three := curve.ScalarMul(base, 3)
	miMC.Write(U.X, U.Y, V.X, V.Y, _Y.X, _Y.Y, Three.X, Three.Y)
	hOut2 := miMC.Sum()

	hBits := api.ToBinary(hOut, 256)
	hBits1 := api.ToBinary(hOut1, 256)
	hBits2 := api.ToBinary(hOut2, 256)

	vBits := api.ToBinary(circuit.R, 256)
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

	return nil

}
