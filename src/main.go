package main

import (
	"crypto/rand"
	"fmt"
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

// As defined in the paper, VK is an output of the Generator function; and inputs for the Prover and Verifier functions.
type VK struct {
	vk_PCD groth16.VerifyingKey
	p_s    signature.PublicKey
}

// As defined by the paper. Section IV, A. Construction.
type Proof struct {
	digital_sig    []byte
	PCD_proof      groth16.Proof
	public_witness witness.Witness
}

// This is a gnark circuit struct for a signed message.
// The message is private, but the signature and public keys are known to verifiers.
type eddsaCircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",secret"`
}

// We define the compliance predicate when given a specific circuit.
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
	image.Metadata["length"] = 3
	image.Metadata["height"] = 2
	// This is not necessary, but can be useful information to editors and verifiers who want to know
	// what kind of transformations were permitted.
	image.Metadata["permissibleT"] = "Identity"

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

	fmt.Println("[Editor/Prover] Successfully converted digital signature to PCD proof (Identity transformation).")

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
	// ---------------------------------------------------------------------------------------------------------------
	// ---------------------------------------------------------------------------------------------------------------
	// This is a demonstration of the project's Limitations.
	// I was unable to construct a 2D array of frontend.Variable representing pixels.
	// Without a 2D array, transformations of a Matrix of pixels is hard to describe using the frontend.API.
	// I have created a Gihub issue for this (https://github.com/Consensys/gnark/issues/798) and found a similar issue
	// posted back in Jan, 2022, and is still open to this day (https://github.com/Consensys/gnark/issues/236).

	// If you uncomment the code below this line, and run "go run main.go", you will get this error:
	// 16:26:11 INF compiling circuit
	// 16:26:11 INF parsed circuit inputs nbPublic=9 nbSecret=9
	// 16:26:11 INF building constraint builder nbConstraints=1
	// 16:26:11 WRN circuit has unconstrained inputs
	// panic: unrecognized R1CS curve type
	// goroutine 1 [running]:
	// github.com/consensys/gnark/backend/groth16.Setup({0x0?, 0x0?})
	// 		/home/$/go/pkg/mod/github.com/consensys/gnark@v0.8.0/backend/groth16/groth16.go:286 +0x4a5
	// main.main()
	// 		/home/$/PhotoProof/src/main.go:x +0x7c
	// exit status 2

	// Which points to the `pk, vk, _ := groth16.Setup(ccs)` line.
	// ----------------------------------------------------------------------------------

	// compiles our circuit into a R1CS
	var circuit Matrix
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition

	a := [3][3]frontend.Variable{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}

	b := [3][3]frontend.Variable{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}

	assignment := Matrix{X: a, Y: b} // X is secret, Y is public.
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness) // This proof can be sent alongside verification and public witness Y (i.e. the output).
	groth16.Verify(proof, vk, publicWitness)
}

// A Matrix consists of two fields N=16
type Matrix struct {
	X [3][3]frontend.Variable `gnark:"X, secret"` // X = [N*N]frontend.Variable
	Y [3][3]frontend.Variable `gnark:",public"`
}

func (circuit *Matrix) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Y[0][2], circuit.X[0][2])
	return nil
}
