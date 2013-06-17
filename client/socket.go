// +build !windows

package client

import (
	"syscall"
)

func SetReuseAddr(fd uintptr, use int) {
	syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, use)
}
