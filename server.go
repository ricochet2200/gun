package main

import (
	"github.com/ricochet2200/gun/server"
)

func main() {
	server := server.NewServer(8022)
	server.StartTCP()
}
