package client

import (
	"github.com/ricochet2200/gun/msg"
	"io"
)

type Connection struct {
	msg *msg.Message
	out io.ReadWriteCloser
}

