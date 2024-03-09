package camera

import (
	"fmt"
)

type Transformation struct {
	name   string
	params map[string]interface{}
}

const (
	T0_ = 0 // Identity transformation
	T1_ = 1 // Contrast Increment of 1
	T2_ = 2 // Change Author's name
)

// Runs the transformation on a copy of img1 and checks if the transformed image is equal to img2.
func (img1 Image) TransformCheck(img2 Image, t int, params interface{}) bool {
	if t == T0_ {
		if img1.Equals(img2) {
			fmt.Print("Image A's identity transformation is permissible and results in Image 2.\n\n")
			return true
		} else {
			return false
		}
	}
	if t == T1_ {
		imgT := img1.ContrastIncrement(params.(int))
		if imgT.Equals(img2) {
			fmt.Print("Image A's ContrastIncrement transformation is permissible and results in Image 2.\n\n")
			return true
		} else {
			return false
		}
	}
	if t == T2_ {
		imgT := img1.ChangeAuthor(params.(string))
		if imgT.Equals(img2) {
			fmt.Print("Image A's ChangeAuthor transformation is permissible and results in Image 2.\n\n")
			return true
		} else {
			return false
		}
	}
	return false
}

// Transformation that adds +1 to each pixel value
func (img Image) ContrastIncrement(increment int) Image {
	output := img.Copy_Image()

	// Iterates over the output image's matrix pixel values and
	for i := 0; i < len(img.Matrix); i++ {
		for j := 0; j < len(img.Matrix[0]); j++ {
			// Add increment if pixel value is less than or equal to (255 - increment)
			if img.Matrix[i][j] <= (255 - increment) {
				output.Matrix[i][j] = img.Matrix[i][j] + increment
			}
		}
	}

	return output
}

// Change the author field of the metadata of the given image img to newAuthor
func (img Image) ChangeAuthor(newAuthor string) Image {
	output := img.Copy_Image()
	output.Metadata["author"] = newAuthor

	return output
}
