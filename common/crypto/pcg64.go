package crypto

/*
#cgo LDFLAGS: -L${SRCDIR}/../../pcg64ffi/target/release -lpcg64ffi
#include <stdint.h>
void pcg64_shuffle_bits(uint8_t* data, uintptr_t len, const uint8_t* key, uintptr_t key_len, const uint8_t* seed, uintptr_t seed_len);
void pcg64_unshuffle_bits(uint8_t* data, uintptr_t len, const uint8_t* key, uintptr_t key_len, const uint8_t* seed, uintptr_t seed_len);
*/
import "C"
import "unsafe"

func pcgShuffleBits(data []byte, key []byte, seed []byte) {
	if len(data) == 0 {
		return
	}
	C.pcg64_shuffle_bits((*C.uint8_t)(unsafe.Pointer(&data[0])), C.ulong(len(data)), (*C.uint8_t)(unsafe.Pointer(&key[0])), C.ulong(len(key)), (*C.uint8_t)(unsafe.Pointer(&seed[0])), C.ulong(len(seed)))
}

func pcgUnshuffleBits(data []byte, key []byte, seed []byte) {
	if len(data) == 0 {
		return
	}
	C.pcg64_unshuffle_bits((*C.uint8_t)(unsafe.Pointer(&data[0])), C.ulong(len(data)), (*C.uint8_t)(unsafe.Pointer(&key[0])), C.ulong(len(key)), (*C.uint8_t)(unsafe.Pointer(&seed[0])), C.ulong(len(seed)))
}
