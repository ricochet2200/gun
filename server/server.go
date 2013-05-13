package server

import (
	"../msg"
	"log"
	"net"
	"strconv"
)

type Server struct {
	port int
}

func NewServer(port int) *Server {
	return &Server{port}
}

func (this *Server) StartTCP() error {

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(this.port))
	if err != nil {
		log.Fatal(err)
		return err
		// TODO: handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		raddr := conn.RemoteAddr()
		if raddr == nil { // If null it is probably localhost
			raddr = conn.LocalAddr()
			log.Println("Using localAddr because remote is null", raddr)
		}

		ip := raddr.(*net.TCPAddr).IP
		port := raddr.(*net.TCPAddr).Port
		go this.handleConnection(conn, ip, port)
	}
	return nil
}

func (this *Server) StartUDP() error {

	port := strconv.Itoa(this.port)
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
	if err != nil {
		log.Println("Resolv..")
		return nil
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
		return err
		// TODO: handle error
	}
	for {
		raddr := conn.RemoteAddr()
		if raddr == nil { // If null it is probably localhost
			raddr = conn.LocalAddr()
			log.Println("Using localAddr because remote is null", raddr)
		}

		ip := raddr.(*net.UDPAddr).IP
		port := raddr.(*net.UDPAddr).Port
		this.handleConnection(conn, ip, port)
	}
	return nil
}

func (this *Server) handleConnection(conn net.Conn, ip net.IP, port int) {
	log.Println("Recieved Message from client")
	req, err := msg.DecodeMessage(conn)
	if err != nil {
		log.Println(err)
		return
	}

	switch req.Type() {
	case msg.Binding | msg.Request:

		log.Println("Binding to address:", ip, port)
		res := msg.NewResponse(msg.Success|msg.Binding, req)
		xorAddr := msg.NewXORAddress(ip, port, res.Header())
		res.AddAttribute(xorAddr)

		log.Println("Responding\n\n", res)
		conn.Write(res.EncodeMessage())
	}

}
