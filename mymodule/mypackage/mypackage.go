package mypackage

import (
	"fmt"
	"mymodule/otherpackage"
)

func PrintHello() {
	fmt.Println("Hello from mypackage")
	otherpackage.PrintHello("mypackage says Hello from otherpackage!")
	PrintHello2()
}
