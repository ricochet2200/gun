package main

import (
	"./server"
)

func main() {
	server := server.NewServer(8022)
	server.StartTCP()
}