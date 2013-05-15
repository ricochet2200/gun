package main

import (
	"github.com/ricochet2200/gun/client"
	"log"
)


const ServerHost = "localhost:8022"

func main() {
	client := client.NewClient(ServerHost, "user", "password")

	ip, port, err := client.Bind()
	log.Println(ip, port, err)
}
