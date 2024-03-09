package field_elements

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// Input: []bytes
// Output: []bytes
// This function is required when digitally signing an array of bytes, (e.g. JSON encoded struct),
// the message bytes must be defined as the z value of a field element, as a big endian slice.
// Otherwise you may get this error: "runtime error: slice bounds out of range"

func Bytes_to_big_endian(bytes []byte) []byte {
	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(bytes)               // Set the JSON encoded image as the z value for the fr.Element
	big_endian_bytes := msgFr.Marshal() // Convert z value to a big endian slice

	return big_endian_bytes
}
