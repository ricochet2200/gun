package client

import( 
	"syscall"
)

func SetReuseAddr(fd uintptr, use int) {
	handle := syscall.Handle(fd)
	syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, use)
}