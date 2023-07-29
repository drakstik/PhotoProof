/*
This file contains all the possible transformations we work with.

Transformations must be reasoned in terms of matrices, polynomials and numbers.
This is because zk-SNARKs has a hard time reducing things like if statements.
*/

package image

func (imgA Image) Identity(imgB Image) bool {
	b := true

	// Check if all pixels are the same.
	for _, arrA := range imgA.Matrix {
		for _, arrB := range imgB.Matrix {
			for idx, _ := range imgA.Matrix {
				b = (arrA[idx] == arrB[idx]) && b
			}
		}
	}

	// TODO: Check if the Metadata is the same.

	return b
}
