package client

import (
	"github.com/ricochet2200/gun/msg"
	"io"
)

type Connection struct {
	Res *msg.Message
	Out io.ReadWriteCloser
}

