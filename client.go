package main

import (
	"github.com/ricochet2200/gun/client"
	"log"
)

const MaxOutstandingTransactions int = 10
const Rc int = 7     // TODO: make configurable
const RTO int = 3000 // ms.  TODO: Read RCF 2988. TODO: this should be configurable

const ServerHost = "localhost:8022"

func main() {
	client := client.NewClient(ServerHost)

	ip, port, err := client.ConnectTCP()
	log.Println(ip, port, err)
}
