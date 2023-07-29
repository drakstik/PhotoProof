// package main

// import (
// 	"fmt"
// 	img "photoproof/image"
// )

// func main() {
// 	// Example of an image
// 	fmt.Println(img.CreateImage(12, true, "Metadata key", "Metadata value"))

// 	// Example of a JSON encoded version of the image
// 	fmt.Println(img.CreateImage(12, true, "", 0).EncodeImage())

// 	// Example of hashing the image
// 	fmt.Println(img.CreateImage(12, true, "", 0).HashImage())

// 	// Example of verifying the image
// 	image := img.CreateImage(12, true, "", 0)
// 	signature, publicKey := image.HashImage()       // Encodes image before hashing
// 	fmt.Println(image.Verify(signature, publicKey)) // Print true if the image is valid

// 	// Image identity
// 	imageA := img.CreateImage(12, false, "N", 12)
// 	imageB := img.CreateImage(12, false, "N", 12)

// 	fmt.Println(imageA.Identity(imageB))

// 	// Image circuit
// }

/*
PhotoProof first translates a set of permissible transformations into a compliance predicate.
Given two images, PhotoProof checks whether the images represent permissible transformation's input/output pair.

Examples of some permissible transformations:
- Identity
- Image rotation
- Contrast/Brightness
*/

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	img "photoproof/image"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// As defined in the paper. PK is an output of the Generator function; and inputs for the Prover and Verifier functions.
type PK struct {
	pk_PCD groth16.ProvingKey
	p_s    signature.PublicKey
}

// As defined in the paper. VK is an output of the Generator function; and inputs for the Prover and Verifier functions.
type VK struct {
	vk_PCD groth16.VerifyingKey
	p_s    signature.PublicKey
}

// Define a circuit that will check:
//   - Whether T is permissible,
//   - Whether M1 can become M2, under T (i.e. AssertIsEqual(M2 = T(M1)))
// func (image ImageIdentityCircuit) Define(api frontend.API) error {
// 	for row := range image.M1.PixelRows {
// 		for p := range row.Pixel {

// 		}
// 	}
// }

// As defined by the paper.
type Proof struct {
	digital_sig    []byte
	PCD_proof      groth16.Proof
	public_witness witness.Witness
}

type eddsaCircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",secret"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
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

	// Verify the signature
	eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)

	return nil
}

type imageCircuit struct {
	EddsaCirc eddsaCircuit
	Matrix    frontend.Variable // The encoded Matrix of an Image (must be manipulable in this encoded version)
	N         frontend.Variable
}

// Convert the signature to PCD proof (Note: Only Identity transformations are implemented!)
func proverPCD(proofIn Proof, image img.Image, pk_pp PK) (Proof, VK) {
	msg := image.EncodeImage() // JSON encode the image

	// Create an eddsaCircuit struct, which has a Define() function from gnark's frontend.API that describes the circuit as a constraint system.
	var circuit eddsaCircuit
	// Compile the circuit into a constraint system using a BN254 companion curve
	constraint_system, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// Generate a proving and verifying key
	pk, vk, err := groth16.Setup(constraint_system)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Assign message value to the circuit, as a secret witness
	circuit.Message = msg

	// Get the public key bytes
	_publicKey := pk_pp.p_s.Bytes()
	// Assign public key values to the circuit
	circuit.PublicKey.Assign(1, _publicKey[:32])

	// Assign signature values to the circuit
	circuit.Signature.Assign(1, proofIn.digital_sig)

	// Create a witness from the circuit
	witness, _ := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	// Get the public witness only
	publicWitness, _ := witness.Public()

	// generate the proof using the constraint system, proving key and [public | secret] witness
	proofPCD, _ := groth16.Prove(constraint_system, pk, witness)

	// Populate the proof struct (according to the paper)
	proofOut := Proof{PCD_proof: proofPCD, public_witness: publicWitness}
	// Populate the verification key struct (according to the paper)
	vkOut := VK{vk_PCD: vk}

	return proofOut, vkOut
}

// This process is a pre-processing step and assumed to be executed only once and in advance by a trusted party.
func generator(image img.Image) (PK, VK, signature.Signer, error) {
	/*  From the paper:
	"generate a secret key and a public key for the signature scheme"
	*/

	signingKey, err := ceddsa.New(1, rand.Reader) // Generate a signing key
	if err != nil {
		fmt.Println(err.Error())
	}

	publicKey := signingKey.Public() // Generate a public signature verification key

	/*	From the paper:
		"generate an Fp-R1CS instance which computes a permissible compliance predicate when applied on N-images."
	*/

	// Define an eddsaCircuit, which has a Define() function that utilizes the frontend.API by gnark to translate an
	// arithmatic circuit into a constraint system under the hood.
	var circuit eddsaCircuit

	// Compiling the constraint system for an eddsaCircuit
	// Note: Only the Identity transformation is allowed by the eddsaCircuit for now.
	//		 Please see the Limitations section in the project paper submitted alongside this code.
	constraint_system, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println(err.Error())
	}

	/*	From the paper:
		"generate PCD keys"
	*/
	provingKey, verifyingKey, err := groth16.Setup(constraint_system)
	if err != nil {
		fmt.Println(err.Error())
	}
	pk := PK{pk_PCD: provingKey, p_s: publicKey}
	vk := VK{vk_PCD: verifyingKey, p_s: publicKey}

	return pk, vk, signingKey, err
}

// As described by the paper.
func verifier(vk_pp VK, image img.Image, proof Proof) bool {
	if proof.PCD_proof == nil { // Case: Proof is a digital signature.
		// Encode image.
		msg := image.EncodeImage() // []byte{0xde, 0xad, 0xf0, 0x0d, 0x0d}

		// The size of the message must be a multiple of the size of Fr or you can get runtime error:
		// "runtime error: slice bounds out of range"
		var msgFr fr.Element
		msgFr.SetBytes(msg)   // Set z value for the fr.Element
		msg = msgFr.Marshal() // Convert z value to a big endian slice

		// Instantiate hash function.
		hFunc := hash.MIMC_BN254.New()

		// Verify digital signature.
		isValid, err := vk_pp.p_s.Verify(proof.digital_sig, msg, hFunc)
		if err != nil {
			fmt.Println(err.Error())
		}
		return isValid
	} else { // Case: Proof is a PCD proof.
		// Verify the PCD proof.
		err := groth16.Verify(proof.PCD_proof, vk_pp.vk_PCD, proof.public_witness)
		if err != nil {
			// Invalid proof.
			return false
		} else {
			// Valid proof.
			return true
		}
	}
}

type Matrix struct {
	X [16]frontend.Variable `gnark:"X, secret"` // X = [N*N]frontend.Variable
	Y [16]frontend.Variable `gnark:",public"`
}

func (circuit *Matrix) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Y, circuit.X)
	return nil
}

func main() {

	/*
		Begin demo.

		---------------------------------------------------------------------------------------------------------------------------
		[Trusted Camera] Generating keys, signing original image,
	*/

	N := 6 // In this implementation N is a multiple of 3, where N/2 = number of pixels.

	// Simulating taking a picture with secure camera
	image := img.CreateImage(N, true, "", 0)

	// Adding metadata to the image (this is for example)
	image.Metadata["author"] = "David Mberingabo"
	image.Metadata["lengthxheight"] = "3x2"
	image.Metadata["permissibleT"] = "Editors can crop out the the first pixel" // This is not necessary, but can be useful to editors and verifiers.

	// Keys generated by secure camera
	provingKeyPCD, verifyingKeyPCD, signingKey, err := generator(image)
	if err != nil {
		fmt.Println("ERROR: [Secure Camera] Attempting to generate keys.")
	}
	fmt.Println("[Secure Camera] Successfully generated keys.")

	// JSON encode image into bytes that can be signed
	JSON_Image := image.EncodeImage() // []byte{0xde, 0xad, 0xf0, 0x0d, 0x0d}

	// The message bytes must be defined as the z value of a field element as a big endian slice or you may get this error:
	// "runtime error: slice bounds out of range"
	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(JSON_Image)                // Set the JSON encoded image as the z value for the fr.Element
	big_endian_bytes_Image := msgFr.Marshal() // Convert z value to a big endian slice

	// Instantiate hash function to be used when signing the image
	hFunc := hash.MIMC_BN254.New()

	// Sign the JSON encoded image. Done by the trusted camera.
	signature, err := signingKey.Sign(big_endian_bytes_Image, hFunc)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("ERROR: [Secure Camera] Attempting to sign image.")
	} else {
		fmt.Println("[Secure Camera] Successfully signed image.")
	}

	// Set signature as a field of the Proof struct defined in the paper.
	proof_sig := Proof{digital_sig: signature}

	/*
		---------------------------------------------------------------------------------------------------------------------------
				[Verifier]	Demo of what the verifier needs to verify an original image.
	*/

	// Verify signature. Done by a verifier.
	isValid1 := verifier(verifyingKeyPCD, image, proof_sig)
	if !isValid1 {
		fmt.Println("Error: invalid signature")
	} else {
		fmt.Println("[Verifier] Successfully verified signature.")
	}

	/*
		---------------------------------------------------------------------------------------------------------------------------
				[Editor 0] Creating a proof from a signed image (Currently, only for the identity transformation, so there is no transformation).
	*/
	// Convert signature to proof (Editor 0)
	proofOut, vkOut := proverPCD(proof_sig, image, provingKeyPCD)

	fmt.Println("[Editor/Prover] Successfully converted digital signature to PCD proof.")

	/*
		---------------------------------------------------------------------------------------------------------------------------
				[Verifier] verifying a PCD proof.
	*/
	isValid2 := verifier(vkOut, image, proofOut)
	// verify the proof
	if !isValid2 {
		fmt.Println("Error: invalid proof")
	} else {
		fmt.Println("[Verifier] Successfully verified PCD proof.")
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Compile our circuit into a R1CS
	// var circuit1 eddsaCircuit
	// ccs1, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit1)

	// // groth16 zkSNARK: Setup
	// pk1, vk1, _ := groth16.Setup(ccs1)

	// // witness definition

	// a := twistededwards.Point{X: "0x09391ebe31447725969595c8f5ad764ef922fddfc0f610f7a2b10754f11cfed8",
	// 	Y: "0x2eda0b25b57cdffdc7fd81f4095f51383c896705113103c8f4babd6b3876bb45"}

	// public_key := eddsa.PublicKey{A: a}

	// r := twistededwards.Point{X: "0x09391ebe31447725969595c8f5ad764ef922fddfc0f610f7a2b10754f11cfed8",
	// 	Y: "0x2eda0b25b57cdffdc7fd81f4095f51383c896705113103c8f4babd6b3876bb45"}

	// signature := eddsa.Signature{R: r, S: "0x0517d8a014374a1c51858a871a9702f7fa843de46f54c4a3af46a94a619bf10d"}

	// message := hashStringToBigInt("I love gnark") // Secret

	// assignment1 := eddsaCircuit{PublicKey: public_key, Signature: signature, Message: message}
	// witness1, _ := frontend.NewWitness(&assignment1, ecc.BN254.ScalarField())
	// publicWitness1, _ := witness1.Public()

	// // groth16: Prove & Verify
	// proof1, _ := groth16.Prove(ccs1, pk1, witness1)
	// groth16.Verify(proof1, vk1, publicWitness1)

	// ----------------------------------------------------------------------------------
	// compiles our circuit into a R1CS
	// var circuit Matrix
	// ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// // groth16 zkSNARK: Setup
	// pk, vk, _ := groth16.Setup(ccs)

	// // witness definition
	// row := [16]frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	// row2 := [16]frontend.Variable{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	// // row2 := [3]frontend.Variable{1, 2, 3}
	// // row3 := [3]frontend.Variable{1, 2, 3}

	// // x := [3][3]frontend.Variable{row, row2, row3}

	// assignment := Matrix{X: row, Y: row2} // X is secret, Y is public.
	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// publicWitness, _ := witness.Public()

	// // groth16: Prove & Verify
	// proof, _ := groth16.Prove(ccs, pk, witness) // This proof can be sent alongside verification and public witness Y (i.e. the output).
	// groth16.Verify(proof, vk, publicWitness)
}

func hashStringToBigInt(str string) *big.Int {
	encodedInt := new(big.Int)
	encodedInt.SetString(hex.EncodeToString([]byte(str)), 16)
	return encodedInt
}
