package camera

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// This circuit is defined only for transformations T0 and T1.
type Contrast_Increment_Circuit struct {
	PublicKey_in                eddsa.PublicKey      `gnark:",secret"` // (for generator)
	PublicKey_out               eddsa.PublicKey      `gnark:",public"` // (for prover)
	Signature                   eddsa.Signature      `gnark:",secret"` // (for generator)
	Image_in                    Image                `gnark:",public"` // (for prover)
	Image_out                   Image                `gnark:",public"` // (for prover)
	T                           frontend.Variable    `gnark:",public"` // (for prover)
	Permissible_Transformations [2]frontend.Variable `gnark:",public"`
	IsDigitalSig                bool                 `gnark:",public"`
}

// When compiled, this definition is garbled under the hood and compiled as a compliance predicate.
// If there are no transformations set in the circuit, Identity is checked using Signature.
// Else, run the transformation set in the circuit
func (circuit *Contrast_Increment_Circuit) Define(api frontend.API) error {
	// If this is a digital signature, verify the digital signature using image_out and its public key.
	if len(circuit.Image_in.Matrix) == 0 && circuit.T == nil {

		// Set the twisted edwards curve to use
		curve, err := twistededwards.NewEdCurve(api, 1)
		if err != nil {
			return err
		}

		// Create a hash function
		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}

		// Assert that circuit.Signature matches the digital signature of the JSON encoding of circuit.Image_out
		// NOTE: Gnark's eddsa uses api.AssertIsEqual
		encoded_Image_out := circuit.Image_out.JSON_Encode_Image() // JSON encode Image_out
		eddsa.Verify(curve, circuit.Signature, encoded_Image_out, circuit.PublicKey_out, &mimc)

		// Exit function
		return nil
	}

	// Assert that the transformation T is permissible, i.e. check that T is in Permissible_Transformations
	notPermissible := frontend.Variable(1) // T is permissible if this value is 0
	for i := 0; i < len(circuit.Permissible_Transformations); i++ {
		// notPermissible = notPermissible * (1 - ((Permissible_Transformations[i] - T) == 0))
		notPermissible = api.Mul(notPermissible, api.Sub(1, api.IsZero(api.Sub(circuit.Permissible_Transformations[i], circuit.T))))
	}
	api.AssertIsEqual(notPermissible, 0)

	// Assert that public keys are also equivalent.
	api.AssertIsEqual(circuit.PublicKey_out.A.X, circuit.PublicKey_in.A.X)

	// api.AssertIsEqual(circuit.Image_in.TransformCheck(circuit.Image_out, 1, 1), true)

	// // First, assert that images are equal when img1 is transformed,
	// api.AssertIsEqual(camera.IsPermissible(circuit.Transformation, circuit.Image_in), true)
	// // Second, check if the transformation is permissible,
	// api.AssertIsEqual(circuit.Image_in.TransformCheck(circuit.Image_out, circuit.Transformation, circuit.Params), true)
	// // Third, check if the public keys are equal
	// api.AssertIsEqual(reflect.DeepEqual(circuit.PublicKey_in, circuit.PublicKey_out), true)

	return nil
}

// Can you write the TransformCheck function as a circuit and call it above??
// First hint, understand how nestled circuit functions are written and loops.
// Second hint, this is only for a +1 contrast increment.
// func (circuit *Contrast_Increment_Circuit) TransformCheck_(api frontend.API) error {

// }
