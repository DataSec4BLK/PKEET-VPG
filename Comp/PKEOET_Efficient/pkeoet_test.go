package main

import (
	"testing"
)

func TestEncDec(t *testing.T) {
	crs, _ := Setup()
	user, err := UKG(crs)
	if err != nil {
		t.Error(err)
	}
	m := getRandomGT()
	ct, err := Enc(crs, user.PK, m)
	if err != nil {
		t.Error(err)
	}
	m_, err := Dec(crs, ct, user.SK)
	if err != nil {
		t.Error(err)
	}

	if !m.Equal(m_) {
		t.Error("m != m_")
	}
}

func TestPDTest(t *testing.T) {
	crs, _ := Setup()
	user, err := UKG(crs)
	if err != nil {
		t.Error(err)
	}
	disc, err := DKG(crs)
	if err != nil {
		t.Error(err)
	}
	tracer, err := TKG(disc.dpk, user.SK)
	if err != nil {
		t.Error(err)
	}

	m1 := getRandomGT()
	m2 := getRandomGT()

	ct1, err := Enc(crs, user.PK, m1)
	if err != nil {
		t.Error(err)
	}
	ct2, _ := Enc(crs, user.PK, m1)
	ct3, _ := Enc(crs, user.PK, m2)

	ptr1, err := PTest(ct1, ct2, tracer, tracer)
	ptr2, err := PTest(ct1, ct3, tracer, tracer)

	if DTest(ptr1, disc.dsk) != nil {
		t.Error("ptr1 error")
	}
	if DTest(ptr2, disc.dsk) == nil {
		t.Error("ptr2 error")
	}
}

func BenchmarkPTest(b *testing.B) {
	crs, _ := Setup()
	user, err := UKG(crs)
	if err != nil {
		b.Error(err)
	}
	disc, err := DKG(crs)
	if err != nil {
		b.Error(err)
	}
	tracer, err := TKG(disc.dpk, user.SK)
	if err != nil {
		b.Error(err)
	}

	m1 := getRandomGT()

	ct1, err := Enc(crs, user.PK, m1)
	if err != nil {
		b.Error(err)
	}
	ct2, _ := Enc(crs, user.PK, m1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PTest(ct1, ct2, tracer, tracer)
	}
}

func BenchmarkDTest(b *testing.B) {
	crs, _ := Setup()
	user, err := UKG(crs)
	if err != nil {
		b.Error(err)
	}
	disc, err := DKG(crs)
	if err != nil {
		b.Error(err)
	}
	tracer, err := TKG(disc.dpk, user.SK)
	if err != nil {
		b.Error(err)
	}

	m1 := getRandomGT()

	ct1, err := Enc(crs, user.PK, m1)
	if err != nil {
		b.Error(err)
	}
	ct2, _ := Enc(crs, user.PK, m1)

	ptr1, err := PTest(ct1, ct2, tracer, tracer)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DTest(ptr1, disc.dsk)
	}
}
