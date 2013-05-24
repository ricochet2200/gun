package server

import (
	"github.com/ricochet2200/gun/msg"
	"io"
	"net"
)

type Connection struct {
	Req *msg.Message
	Out io.Writer
	IP net.IP
	Port int
	User string
	Passwd string
	Realm string
	HasAuth bool
}

func (this *Connection) Write(res *msg.Message) {

	xorAddr := msg.NewXORAddress(this.IP, this.Port, res.Header())
	res.AddAttribute(xorAddr)
	
	if this.HasAuth {
		i := msg.NewIntegrityAttr(this.User, this.Passwd, this.Realm, this.Req)
		res.AddAttribute(i)
	}

	this.Out.Write(res.EncodeMessage())
}