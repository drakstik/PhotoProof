package image

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
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
