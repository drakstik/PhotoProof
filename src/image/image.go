package image

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
)

/*
PhotoProof defines an image as a NxN matrix and some metadata M (i.e. I = (NxN, M)).
*/
type Image struct {
	Matrix   [][]int                `json:"matrix"` // Each group of three
	Metadata map[string]interface{} `json:"metadata"`
}

// Return an NxN image, given N as a parameter.
// Randomly populate the Matrix as an array of arrays of integers between 0 and 255 to represent pixels
func CreateImage(N int, flag bool, metakey string, metavalue interface{}) Image {
	// create a 2D array of size N*N
	arr2D := make([][]int, N)

	// Set random integers in the 2D array
	for i := range arr2D {
		arr2D[i] = make([]int, N)
		for j := range arr2D[i] {
			if flag {
				// Seed the random number generator
				rand.New(rand.NewSource(time.Now().UnixNano()))

				arr2D[i][j] = rand.Intn(256)
			} else {
				arr2D[i][j] = 5
			}
		}
	}

	// Instantiate image
	image := Image{Matrix: arr2D, Metadata: make(map[string]interface{})}
	// add Metadata to the image
	image.Metadata[metakey] = metavalue

	return image
}

// Return the JSON encoded version of an image.
func (image Image) EncodeImage() []byte {
	encoded_image, err := json.Marshal(image)
	if err != nil {
		fmt.Println("Error while encoding image: " + err.Error())
		return []byte{}
	}

	return encoded_image
}

// Return a hash signature of the image and the public key for verification
func (image Image) HashImage() ([]byte, ecdsa.PublicKey) {
	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// create a ecdsa key pair
	privateKey, err := ecdsa.GenerateKey(crand.Reader)
	if err != nil {
		fmt.Println("Error while hashing image: " + err.Error())
		return []byte{}, ecdsa.PublicKey{}
	}

	publicKey := privateKey.PublicKey

	// Encode image
	b := image.EncodeImage()

	var msgFr fr.Element
	msgFr.SetBytes(b)
	msg := msgFr.Marshal()

	// sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		fmt.Println("Error while hashing image: " + err.Error())
		return []byte{}, ecdsa.PublicKey{}
	}

	return signature, publicKey
}

// Verify the image, given the signature and public key
// Returns true if the image and signature match, false otherwise.
func (image Image) Verify(signature []byte, publicKey ecdsa.PublicKey) bool {
	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// Encode image
	b := image.EncodeImage()

	var msgFr fr.Element
	msgFr.SetBytes(b)
	msg := msgFr.Marshal()

	// verify that image matches signature
	validity, err := publicKey.Verify(signature, msg, hFunc)
	if err != nil {
		fmt.Println("Error while verifying image: " + err.Error())
		return false
	}

	return validity
}
