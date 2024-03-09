package camera

import (
	"PhotoProof/v2/field_elements"
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// As defined in the paper. PK is an output of the Generator function; and inputs for the Prover and Verifier functions.
type PK struct {
	PK_PCD    groth16.ProvingKey
	PK_DigSig signature.PublicKey
}

type PK_Msg struct {
	PK_PCD    groth16.ProvingKey
	PK_DigSig []byte
}

// As defined in the paper, VK is an output of the Generator function; and inputs for the Prover and Verifier functions.
type VK struct {
	VK_PCD    groth16.VerifyingKey
	PublicKey signature.PublicKey
}

type VK_Msg struct {
	VK_PCD    groth16.VerifyingKey
	PublicKey []byte
}

// As defined by the paper. Section IV, A. Construction.
type Proof struct {
	Digital_sig    []byte
	PCD_proof      groth16.Proof
	Public_witness witness.Witness
	VK             VK
	PK             PK
}

type Proof_Msg struct {
	Digital_sig    []byte
	PCD_proof      groth16.Proof
	Public_witness []byte
	VK             VK_Msg
	PK             PK_Msg
}

// Input: an image (I).
// Output: sk, pk, vk
// It uses ceddsa "github.com/consensys/gnark-crypto/signature/eddsa" as the security parameter discussed in the paper
// to generate a secret signing key (sk), a groth16.ProvingKey (pk), and a groth16.VerifyingKey (vk)
func Generator(I Image) (Proof, error) {
	/*  From the paper:
	"generate a secret key and a public key for the signature scheme"
	*/
	secretKey, err := eddsa.New(1, rand.Reader) // Generate a signing key
	if err != nil {
		fmt.Println(err.Error())
	}

	publicKey := secretKey.Public() // Generate a public signature verification key

	/*	From the paper:
		"generate an Fp-R1CS instance which computes a permissible compliance predicate when applied on N-images."
	*/

	// Define an eddsaCircuit, which has a Define() function that utilizes the frontend.API by gnark to translate an
	// arithmatic circuit into a constraint system under the hood.
	var circuit Contrast_Increment_Circuit

	// assign Image_in (since Generator is done within the camera)
	circuit.Image_in = I

	// assign Permissible_Transformations
	var permissibleT []frontend.Variable
	permissibleT = I.Metadata["permissibleT"].([]frontend.Variable)
	for i := 0; i < len(circuit.Permissible_Transformations); i++ {
		circuit.Permissible_Transformations[i] = permissibleT[i]
	}

	/* Sign the image into a normal digital signature */
	// public key bytes in should be the public key
	publicKey_in_Bytes := publicKey.Bytes()
	// assign PublicKey_in
	circuit.PublicKey_in.Assign(twistededwards.ID(ecc.BN254), publicKey_in_Bytes[:32])

	// Instantiate hash function to be used when signing the image
	hFunc := hash.MIMC_BN254.New()

	JSON_encoded_image := I.JSON_Encode_Image()
	Image_big_endian_bytes := field_elements.Bytes_to_big_endian(JSON_encoded_image)

	// Sign the big endian encoded image.
	signature, err := secretKey.Sign(Image_big_endian_bytes, hFunc)
	if err != nil {
		fmt.Println("ERROR 0: " + err.Error())
		// Return error
		return Proof{}, err
	}

	// assign Signature
	circuit.Signature.Assign(twistededwards.ID(ecc.BN254), signature)

	/* Compiling the constraint system for an eddsaCircuit */
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println(err.Error())
	}

	/*	"generate PCD keys"	*/
	provingKey, verifyingKey, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err.Error())
	}

	/* Create initial Proof without the PCD Proof*/
	pk := PK{PK_PCD: provingKey, PK_DigSig: publicKey}   // Prover needs PCD proving key and public key of signed image
	vk := VK{VK_PCD: verifyingKey, PublicKey: publicKey} // Verifier needs PCD verifying key and public key of signed image

	proof_sig := Proof{Digital_sig: signature, VK: vk, PK: pk}

	/* Generate the witness */
	// NOTE: This witness includes both secret and public fields!!!
	// fmt.Println(circuit)
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("ERROR 1: " + err.Error())
		// Return error
		return proof_sig, err
	}

	/* Generate the public part of the witness */
	// NOTE: This is ok to share with public
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("ERROR 2: " + err.Error())
		// Set public witness
		proof_sig.Public_witness = publicWitness
		// Return error
		return proof_sig, err
	}

	/* Generate the proof */
	proof, err := groth16.Prove(r1cs, provingKey, witness)
	if err != nil {
		fmt.Println("ERROR 3: " + err.Error())
		// Set signature as a field of the Proof struct defined in the paper.
		proof_sig = Proof{Digital_sig: signature, PCD_proof: proof, Public_witness: publicWitness, VK: vk, PK: pk}
		// Return error
		return proof_sig, err
	}

	return proof_sig, nil
}

// type ComplianceCircuit struct {
// 	PublicKey_in   eddsa.PublicKey `gnark:",public"`
// 	PublicKey_out  eddsa.PublicKey `gnark:",public"`
// 	Signature      eddsa.Signature `gnark:",public"`
// 	Image_in       Image           `gnark:",public"`
// 	Image_out      Image           `gnark:",public"`
// 	Transformation string          `gnark:",public"`
// 	Params         interface{}     `gnark:",public"`
// 	IsDigitalSig   bool            `gnark:",public"`
// }

// // When compiled, this definition is garbled under the hood and compiled as a compliance predicate.
// // If there are no transformations set in the circuit, Identity is checked using Signature.
// // Else, run the transformation set in the circuit
// func (circuit *ComplianceCircuit) Define(api frontend.API) error {

// 	/*
// 		Assert that Image_in has the Signature in the circuit.
// 	*/

// 	// Set the twisted edwards curve to use
// 	curve, err := twistededwards.NewEdCurve(api, 1)
// 	if err != nil {
// 		return err
// 	}

// 	// Create a hash function
// 	mimc, err := mimc.NewMiMC(api)
// 	if err != nil {
// 		return err
// 	}

// 	// Assert that circuit.Signature was derived from the JSON encoding of circuit.Image_in
// 	// NOTE: Gnark's eddsa uses api.AssertIsEqual
// 	encoded_Image_in := circuit.Image_in.JSON_Encode_Image() // JSON encode Image_in
// 	eddsa.Verify(curve, circuit.Signature, encoded_Image_in, circuit.PublicKey_out, &mimc)

// 	// If the input image and transformations are nil and the circuit is that of a digital signature
// 	// then the constraint system should simply assert that the Image_out matches the digital signature and exit.
// 	if circuit.Image_in.Matrix == nil && circuit.Transformation == "" && circuit.IsDigitalSig {
// 		// Assert that circuit.Signature matches the digital signature of the JSON encoding of circuit.Image_out
// 		// NOTE: Gnark's eddsa uses api.AssertIsEqual
// 		encoded_Image_out := circuit.Image_out.JSON_Encode_Image() // JSON encode Image_out
// 		eddsa.Verify(curve, circuit.Signature, encoded_Image_out, circuit.PublicKey_out, &mimc)

// 		// Exit function
// 		return nil
// 	}

// 	// // First, assert that images are equal when img1 is transformed,
// 	// api.AssertIsEqual(camera.IsPermissible(circuit.Transformation, circuit.Image_in), true)
// 	// // Second, check if the transformation is permissible,
// 	// api.AssertIsEqual(circuit.Image_in.TransformCheck(circuit.Image_out, circuit.Transformation, circuit.Params), true)
// 	// // Third, check if the public keys are equal
// 	// api.AssertIsEqual(reflect.DeepEqual(circuit.PublicKey_in, circuit.PublicKey_out), true)

// 	return nil
// }
