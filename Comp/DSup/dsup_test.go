package main

import (
	"crypto/rand"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDSup(t *testing.T) {
	_, _, g1, g2 := bls12381.Generators()
	order := bls12381.ID.ScalarField()

	crs := &CRS{&g1, getRandomG1(), &g2, getRandomG2()}

	// User1
	usk1, err := rand.Int(rand.Reader, order)
	if err != nil {
		panic(err)
	}
	upk1 := new(bls12381.G1Affine).ScalarMultiplication(crs.g, usk1)
	user1 := &User{usk1, upk1}

	// User2
	usk2, _ := rand.Int(rand.Reader, order)
	upk2 := new(bls12381.G1Affine).ScalarMultiplication(crs.g, usk2)
	user2 := &User{usk2, upk2}

	// Supervisor
	tsk, _ := rand.Int(rand.Reader, order)
	tpk := new(bls12381.G1Affine).ScalarMultiplication(crs.h, tsk)
	lsk, _ := rand.Int(rand.Reader, order)
	lpk := new(bls12381.G2Affine).ScalarMultiplication(crs.h_, lsk)
	sup := &Supervisor{tsk, lsk, tpk, lpk}

	// Gen records
	dsup1, err := user1.GenDSup(crs, sup.tpk, sup.lpk)
	if err != nil {
		panic(err)
	}
	dsup1_, err := user1.GenDSup(crs, sup.tpk, sup.lpk)
	if err != nil {
		panic(err)
	}
	dsup2, err := user2.GenDSup(crs, sup.tpk, sup.lpk)
	if err != nil {
		panic(err)
	}

	// Trace
	m, err := sup.Trace(dsup1)
	if err != nil {
		panic(err)
	}
	if !user1.upk.Equal(m) {
		t.Error("m and user1.upk do not match")
	}

	// Link
	lskU1, err := sup.LKGen(dsup1)
	if err != nil {
		panic(err)
	}
	assert.Nil(t, Link(crs, dsup1_, lskU1))
	res := Link(crs, dsup2, lskU1)
	if res == nil {
		t.Fatal("Link mistake")
	}
}
