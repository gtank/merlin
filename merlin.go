package merlin

import (
	"encoding/binary"
	"fmt"

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

	fmt.Printf("Initialize STROBE-128(%x)\n", merlinProtocolLabel)

	t.AppendMessage([]byte(domainSeparatorLabel), []byte(appLabel))
	return &t
}

// Append adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessage(label, message []byte) {
	// AD[label || le32(len(message))](message)

	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(message)))

	fmt.Printf("meta-AD : %x || LE32(%d)\t# b\"%s\"\n", label, len(message), label)

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	fmt.Printf("AD : %x\t# b\"%s\"\n", message, message)
	t.s.AD(false, message)
}

// ExtractBytes fills the supplied buffer with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. See the Transcript Protocols section of the Merlin website
// for details on labels.
func (t *Transcript) ExtractBytes(label []byte, outLen int) []byte {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outLen))

	fmt.Printf("meta-AD : %x || LE32(%d)\t# b\"%s\"\n", label, outLen, label)

	// The StrobeGo API does not support continuation operations,
	// so we have to pass the label and length as a single buffer.
	// Otherwise it will record two meta-AD operations instead of one.
	labelSize := append(label, sizeBuffer...)
	t.s.AD(true, labelSize)

	// a PRF call directly to the output buffer would be better
	outBytes := t.s.PRF(outLen)
	fmt.Printf("PRF : %x\n", outBytes)
	return outBytes
}
