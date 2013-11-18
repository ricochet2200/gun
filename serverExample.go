package main

import (
	"github.com/ricochet2200/gun/server"
	"log"
)

type Authenticator struct {
	auth map[string]string
}

func (this *Authenticator) Password(username string) (string, bool) {
	v, ok := this.auth[username]
	return v, ok
}

func main() {

	auth := map[string] string {
		"user": "password",
		"user2": "password",
		"admin": "password",
		"user-linux" : "password",
		"user-windows" : "password",
	}
	v := &Authenticator{auth}

	c := make(chan *server.Connection, 10)

	server := server.NewServer(8022, c, v)
	
	go func() {
		for conn := range c {
			conn = conn
			log.Println("Unrecognized: ", conn.IP, conn.Port)
		}
	}()

	server.Start()
}
