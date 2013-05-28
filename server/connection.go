package server

import (
	"github.com/ricochet2200/gun/msg"
	"net"
)

type Connection struct {
	Req *msg.Message
	Out net.Conn
	User string
	Passwd string
	Realm string
	HasAuth bool
}

func (this *Connection) Port() int {
	return this.Out.RemoteAddr().(*net.TCPAddr).Port
}

func (this *Connection) IP() net.IP {
	return this.Out.RemoteAddr().(*net.TCPAddr).IP
}

func (this *Connection) Write(res *msg.Message) {

	xorAddr := msg.NewXORAddress(this.IP(), this.Port(), res.Header())
	res.AddAttribute(xorAddr)
	
	if this.HasAuth {
		i := msg.NewIntegrityAttr(this.User, this.Passwd, this.Realm, this.Req)
		res.AddAttribute(i)
	}

	this.Out.Write(res.EncodeMessage())
}