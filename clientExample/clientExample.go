package main

import (
	"github.com/ricochet2200/gun/client"
//	"log"
)


const ServerHost = "localhost:8022"

func main() {
	client, err := client.NewClient(ServerHost, "user", "password")
	if err != nil {
		panic(err)
	}

	/*conn, err :=*/ client.Bind()
//	log.Println(conn.IP(), conn.Port(), err)
}
