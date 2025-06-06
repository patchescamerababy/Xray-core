package crypto

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// memoryWriter is a buf.Writer storing written buffers in memory
type memoryWriter struct{ mb buf.MultiBuffer }

func (w *memoryWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mb = append(w.mb, mb...)
	return nil
}

// EnhancedWriter wraps AuthenticationWriter to process first packet bits
type EnhancedWriter struct {
	aw          *AuthenticationWriter
	writer      buf.Writer
	key         []byte
	headerBits  uint32
	firstPacket bool
}

func NewEnhancedWriter(aw *AuthenticationWriter, writer buf.Writer, key []byte, headerBits uint32) *EnhancedWriter {
	return &EnhancedWriter{aw: aw, writer: writer, key: key, headerBits: headerBits, firstPacket: true}
}

func countBits(b []byte) (ones, zeros uint32) {
	for _, bb := range b {
		for j := 0; j < 8; j++ {
			if (bb>>j)&1 == 1 {
				ones++
			} else {
				zeros++
			}
		}
	}
	return
}

func (w *EnhancedWriter) processFirst(data []byte) []byte {
	ones, zeros := countBits(data)
	ones += w.headerBits
	zeros += w.headerBits
	ratio := float32(ones) / float32(zeros)
	var extra uint32
	if ratio > 0.7 && ratio < 1.4 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		if ones <= zeros {
			target := rng.Float32()*(0.7-0.6) + 0.6
			extra = uint32(float32(ones)/target-float32(zeros))/8 + 1
			data = append(data, bytes.Repeat([]byte{0x00}, int(extra))...)
		} else {
			target := rng.Float32()*(1.5-1.4) + 1.4
			extra = uint32(float32(zeros)*target-float32(ones))/8 + 1
			data = append(data, bytes.Repeat([]byte{0xFF}, int(extra))...)
		}
	}
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], extra)
	data = append(data, tail[:]...)
	pcgShuffleBits(data, w.key, w.key)
	return data
}

func (w *EnhancedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstPacket {
		mw := &memoryWriter{}
		orig := w.aw.writer
		w.aw.writer = mw
		if err := w.aw.WriteMultiBuffer(mb); err != nil {
			return err
		}
		w.aw.writer = orig
		bs := make([]byte, mw.mb.Len())
		mw.mb.Copy(bs)
		buf.ReleaseMulti(mw.mb)
		data := bs
		processed := w.processFirst(data)
		b := buf.New()
		b.Write(processed)
		w.firstPacket = false
		return w.writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}
	w.aw.writer = w.writer
	return w.aw.WriteMultiBuffer(mb)
}

// EnhancedReader wraps AuthenticationReader for first packet
type EnhancedReader struct {
	ar          *AuthenticationReader
	key         []byte
	firstPacket bool
}

func NewEnhancedReader(ar *AuthenticationReader, key []byte) *EnhancedReader {
	return &EnhancedReader{ar: ar, key: key, firstPacket: true}
}

func (r *EnhancedReader) processFirst(data []byte) []byte {
	pcgUnshuffleBits(data, r.key, r.key)
	if len(data) < 4 {
		return data
	}
	extra := binary.BigEndian.Uint32(data[len(data)-4:])
	if int(extra)+4 <= len(data) {
		data = data[:len(data)-int(extra)-4]
	}
	return data
}

func (r *EnhancedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.ar.ReadMultiBuffer()
	if err != nil || !r.firstPacket {
		return mb, err
	}
	bs := make([]byte, mb.Len())
	mb.Copy(bs)
	buf.ReleaseMulti(mb)
	outData := r.processFirst(bs)
	b := buf.New()
	b.Write(outData)
	r.firstPacket = false
	return buf.MultiBuffer{b}, nil
}
