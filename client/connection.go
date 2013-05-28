package client

import (
	"github.com/ricochet2200/gun/msg"
	"net"
)

type Connection struct {
	Res *msg.Message
	Out net.Conn
}

