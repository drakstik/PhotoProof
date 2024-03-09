package verifier

import (
	"PhotoProof/v2/camera"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
)

// As described by the paper.
func Verifier(image camera.Image, proof camera.Proof) (bool, error) {
	if proof.PCD_proof == nil { // Case: Proof is a digital signature.
		isValid, err := camera.Verify_Image(image, proof.VK.PublicKey, proof.Digital_sig)
		if err != nil {
			fmt.Println("ERROR: " + err.Error())
		}
		// Exit function
		return isValid, err
	} else { // Case: Proof is a PCD proof.
		// Verify the PCD proof.
		err := groth16.Verify(proof.PCD_proof, proof.VK.VK_PCD, proof.Public_witness)
		if err != nil {
			fmt.Println(err.Error())
			// Invalid proof.
			return false, err
		} else {
			// Valid proof.
			return true, nil
		}
	}
}
