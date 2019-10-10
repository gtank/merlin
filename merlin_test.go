package merlin

import (
	"fmt"
	"testing"
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
