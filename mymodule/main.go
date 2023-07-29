package main

// func main() {
// fmt.Println("Hello from main")
// mypackage.PrintHello() // using mypackage

/*
	This does not work when we try it with next2main.go,
	so everything should be under packages and main.go remains on top
	it's the only one we can run with go run anyways.
*/
// n := Node{}
// n.PrintBye("main.go is saying Hello from node!")

// }

import "fmt"

func main() {
	N := 3 // Size of the N by N array

	// Initialize a 2D array
	array2D := [][]int{
		{103, 2, 30},
		{49, 5, 255},
		{7, 259, 9},
	}
	fmt.Println("Original 2D array:")
	for _, row := range array2D {
		fmt.Println(row)
	}

	// Convert the 2D array to a single integer
	encoded := flatten(array2D, N)
	fmt.Println("Original Encoded:", encoded)

	// Reflect the array on its vertical axis
	// encodedReflected := reflectVertical(encoded, N)
	// fmt.Println("Reflected Encoded:", encodedReflected)

	// Convert the reflected encoded integer back to a 2D array
	decodedReflected := unflatten(encoded, N)
	fmt.Println("Decoded:")
	for _, row := range decodedReflected {
		fmt.Println(row)
	}
}

// Flatten a 2D array into a single integer
func flatten(array [][]int, N int) int {
	flattened := 0
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			flattened = (flattened * 10) + array[i][j]
		}
	}
	return flattened
}

// Reflect the encoded integer on its vertical axis
func reflectVertical(encoded, N int) int {
	reflected := 0
	for i := 0; i < N; i++ {
		row := (encoded % powerOf10(N)) / powerOf10(N-1)
		reflected = (reflected * powerOf10(N)) + reverseDigits(row, N)
		encoded /= powerOf10(N)
	}
	return reflected
}

// Reverse the digits of a number
func reverseDigits(number, N int) int {
	reversed := 0
	for i := 0; i < N; i++ {
		reversed = (reversed * 10) + (number % 10)
		number /= 10
	}
	return reversed
}

// Convert a flattened integer back to a 2D array
func unflatten(flattened, N int) [][]int {
	reconstructed := make([][]int, N)
	for i := 0; i < N; i++ {
		reconstructed[i] = make([]int, N)
		for j := N - 1; j >= 0; j-- {
			reconstructed[i][j] = flattened % 10
			flattened /= 10
		}
	}
	return reconstructed
}

// Calculate the power of 10 for a given exponent
func powerOf10(exponent int) int {
	result := 1
	for i := 0; i < exponent; i++ {
		result *= 10
	}
	return result
}
