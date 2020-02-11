package merlin

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Initialize STROBE-128(4d65726c696e2076312e30)   # b"Merlin v1.0"
// meta-AD : 646f6d2d736570 || LE32(13)    # b"dom-sep"
// AD : 746573742070726f746f636f6c    # b"test protocol"
// meta-AD : 736f6d65206c6162656c || LE32(9)       # b"some label"
// AD : 736f6d652064617461    # b"some data"
// meta-AD : 6368616c6c656e6765 || LE32(32)        # b"challenge"
// PRF: d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615
// test transcript::tests::equivalence_simple ... ok

func TestSimpleTranscript(t *testing.T) {
	mt := NewTranscript("test protocol")
	mt.AppendMessage([]byte("some label"), []byte("some data"))

	cBytes := mt.ExtractBytes([]byte("challenge"), 32)
	cHex := fmt.Sprintf("%x", cBytes)
	expectedHex := "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := NewTranscript("test protocol")
	tr.AppendMessage([]byte("step1"), []byte("some data"))

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		chlBytes = tr.ExtractBytes([]byte("challenge"), 32)
		tr.AppendMessage([]byte("bigdata"), data)
		tr.AppendMessage([]byte("challengedata"), chlBytes)
	}

	expectedChlHex := "a8c933f54fae76e3f9bea93648c1308e7dfa2152dd51674ff3ca438351cf003c"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}

func TestTranscriptRNG(t *testing.T) {
	label := "test protocol"
	t1 := NewTranscript(label)
	t2 := NewTranscript(label)
	t3 := NewTranscript(label)
	t4 := NewTranscript(label)

	comm1 := []byte("Commitment data 1")
	comm2 := []byte("Commitment data 2")

	witness1 := []byte("Witness data 1")
	witness2 := []byte("Witness data 2")

	// t1 will have commitment 1 and t2, t3, t4 will gave same commitment
	t1.AppendMessage([]byte("com"), comm1)
	t2.AppendMessage([]byte("com"), comm2)
	t3.AppendMessage([]byte("com"), comm2)
	t4.AppendMessage([]byte("com"), comm2)

	// t1, t2 will have same witness data
	// t3, t4 will have same witness data
	r1, err := t1.BuildRNG().ReKeyWithWitnessBytes([]byte("witness"), witness1).Finalize(rand.New(rand.NewSource(0)))
	assert.NoError(t, err)

	r2, err := t2.BuildRNG().ReKeyWithWitnessBytes([]byte("witness"), witness1).Finalize(rand.New(rand.NewSource(0)))
	assert.NoError(t, err)

	r3, err := t3.BuildRNG().ReKeyWithWitnessBytes([]byte("witness"), witness2).Finalize(rand.New(rand.NewSource(0)))
	assert.NoError(t, err)

	r4, err := t4.BuildRNG().ReKeyWithWitnessBytes([]byte("witness"), witness2).Finalize(rand.New(rand.NewSource(0)))
	assert.NoError(t, err)
	var (
		s1 = make([]byte, 32)
		s2 = make([]byte, 32)
		s3 = make([]byte, 32)
		s4 = make([]byte, 32)
	)

	n, err := r1.Read(s1)
	assert.NoError(t, err)
	assert.Equal(t, n, 32)

	n, err = r2.Read(s2)
	assert.NoError(t, err)
	assert.Equal(t, n, 32)

	n, err = r3.Read(s3)
	assert.NoError(t, err)
	assert.Equal(t, n, 32)

	n, err = r4.Read(s4)
	assert.NoError(t, err)
	assert.Equal(t, n, 32)

	// s1 shouldn't match with any due to different commitment data
	// s2 shouldn't match with any due to different witness data
	// s3 and s4 match since they same same commitment and witness data, given a bad rng.
	// this says that above no equalities are due to different commitments and witness but not because of RNG
	assert.NotEqual(t, s1, s2)
	assert.NotEqual(t, s1, s3)
	assert.NotEqual(t, s1, s4)

	assert.NotEqual(t, s2, s3)
	assert.NotEqual(t, s2, s4)

	assert.Equal(t, s3, s4)
}
