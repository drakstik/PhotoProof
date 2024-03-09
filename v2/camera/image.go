package camera

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
)

/*
PhotoProof defines an image as a NxN matrix and some metadata M (i.e. I = (NxN, M)).
*/
type Image struct {
	Matrix   [][]int                `json:"matrix"` // Each group of three
	Metadata map[string]interface{} `json:"metadata"`
}

func TakePhotograph() (Image, Proof, error) {
	N := 16 // In this implementation N is a multiple of 3, where N/2 = number of pixels.

	// Simulating taking a picture with secure camera
	image := Create_Image(N, true)

	// Adding metadata to the image (this is for example)
	image.Metadata["author"] = "David Mberingabo"
	image.Metadata["length"] = 5
	image.Metadata["height"] = 5
	// This is not necessary, but can be useful information to editors and verifiers who want to know
	// what kind of transformations were permitted.
	image.Metadata["permissibleT"] = []frontend.Variable{T0_, T1_}

	// Generate the proof for this image

	// NOTE: SECTION V-F, PCD-Based Signatures, states that the camera should generate the PCD proof
	//		 and alongside it a hash of the secret key, and a hash of the certificate so the proof can claim]
	//		 “the image was authorized by a camera which had access to a secret key with this specific hash digest”
	//		 (e.g., by supplying the prover with a hash digest of the key and a hash on the image together with the same key)
	proof, err := Generator(image)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return image, proof, err
	}

	return image, proof, nil
}

// Return an NxN image, given N as a parameter.
// Randomly populate the Matrix as an array of arrays of integers between 0 and 255 to represent pixels
func Create_Image(N int, flag bool) Image {
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

	return image
}

func (img Image) Copy_Image() Image {
	// Duplicate the image's matrix
	duplicate := make([][]int, len(img.Matrix))
	for i := range img.Matrix {
		duplicate[i] = make([]int, len(img.Matrix[i]))
		copy(duplicate[i], img.Matrix[i])
	}

	// Duplicates the image's metadata as well
	duplicate2 := make(map[string]interface{})
	for key, value := range img.Metadata {
		duplicate2[key] = value
	}

	// Assign the duplicate values as fields for the output Image.
	output := Image{Matrix: duplicate, Metadata: duplicate2}

	return output
}

// Returns true if the two images are equal and false if not.
func (img1 Image) Equals(img2 Image) bool {
	// All values in the matrices must equal
	if len(img1.Matrix) == len(img2.Matrix) {
		for i := 0; i < len(img1.Matrix); i++ {
			for j := 0; j < len(img1.Matrix[0]); j++ {
				if img1.Matrix[i][j] != img2.Matrix[i][j] {
					fmt.Print("Images matrices not equal!", "\n\n")
					return false
				}
			}
		}
	} else {
		fmt.Print("Images matrix lengths not equal!", "\n\n")
		return false
	}

	// All values in the map must be equal
	if reflect.DeepEqual(img1.Metadata, img2.Metadata) {
		fmt.Print("Images are equal.", "\n\n")
		return true
	} else {
		fmt.Print("Images metadata not equal!", "\n\n")
		return false
	}

}

// Return the JSON encoded version of an image.
func (image Image) JSON_Encode_Image() []byte {
	encoded_image, err := json.Marshal(image)
	if err != nil {
		fmt.Println("Error while encoding image: " + err.Error())
		return []byte{}
	}

	return encoded_image
}

func Verify_Image(image Image, publicKey signature.PublicKey, dig_sig []byte) (bool, error) {
	// Encode image.
	msg := image.JSON_Encode_Image() // []byte{0xde, 0xad, 0xf0, 0x0d, 0x0d}

	// The size of the message must be a multiple of the size of Fr or you can get runtime error:
	// "runtime error: slice bounds out of range"
	var msgFr fr.Element
	msgFr.SetBytes(msg)   // Set z value for the fr.Element
	msg = msgFr.Marshal() // Convert z value to a big endian slice

	// Instantiate hash function.
	hFunc := hash.MIMC_BN254.New()

	// Verify digital signature.
	isValid, err := publicKey.Verify(dig_sig, msg, hFunc)
	if err != nil {
		fmt.Println("Error: " + err.Error())
	}

	return isValid, nil
}
