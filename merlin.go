package merlin

import (
	"encoding/binary"
	"io"

	"github.com/mimoo/StrobeGo/strobe"
)

const (
	merlinProtocolLabel  = "Merlin v1.0"
	domainSeparatorLabel = "dom-sep"
)

type Transcript struct {
	s strobe.Strobe
}

func NewTranscript(appLabel string) *Transcript {
	t := Transcript{
		s: strobe.InitStrobe(merlinProtocolLabel, 128),
	}

	t.AppendMessage([]byte(domainSeparatorLabel), []byte(appLabel))
	return &t
}

// Append adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessage(label, message []byte) {
	// AD[label || le32(len(message))](message)

	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(message)))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	t.s.AD(false, message)
}

// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. See the Transcript Protocols section of the Merlin website
// for details on labels.
func (t *Transcript) ExtractBytes(label []byte, outLen int) []byte {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outLen))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	// A PRF call directly to the output buffer (in the style of an append API)
	// would be better, but our underlying STROBE library forces an allocation
	// here.
	outBytes := t.s.PRF(outLen)
	return outBytes
}

// BuildRNG returns the TranscriptRNG with the strbe state cloned.
func (t *Transcript) BuildRNG() *TranscriptRNG {
	s := t.s.Clone()
	return &TranscriptRNG{s: *s}
}

type TranscriptRNG struct {
	s strobe.Strobe
}

// ReKeyWithWitnessBytes rekeys the transcript with witness data.
func (t *TranscriptRNG) ReKeyWithWitnessBytes(label, witness []byte) *TranscriptRNG {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(witness)))

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)
	t.s.KEY(witness)
	return t
}

// Finalize uses the supplied rng to re key the transcript.
func (t *TranscriptRNG) Finalize(rng io.Reader) (*TranscriptRNG, error) {
	var randBytes [32]byte
	_, err := rng.Read(randBytes[:])
	if err != nil {
		return nil, err
	}

	t.s.AD(true, []byte("rng"))
	t.s.KEY(randBytes[:])
	return t, nil
}

// Read reads random data and writes to buf
func (t *TranscriptRNG) Read(buf []byte) (int, error) {
	l := len(buf)
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(l))
	t.s.AD(true, sizeBuffer)
	res := t.s.PRF(l)
	return copy(buf, res), nil
}
