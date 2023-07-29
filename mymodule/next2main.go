package main

import "fmt"

type Node struct{}

func (node *Node) PrintBye(s string) {
	fmt.Println(s)
}
