package server

import (
	"github.com/ricochet2200/gun/msg"
	"log"
	"net"
	"strconv"
)

var Realm string = "STUN Server"

type Authenticator interface {
	Password(/*username*/ string) (/*password*/string, /*ok*/bool)
}

type Server struct {
	port int
	conns chan *Connection
	auth Authenticator
}

func NewServer(port int, c chan *Connection, a Authenticator) *Server {
	return &Server{port, c, a}
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

	defer conn.Close()
	log.Println("Recieved Message from client")
	req, err := msg.DecodeMessage(conn)
	if err != nil {
		log.Println(err)
		return
	}

	switch req.Type() {
	case msg.Binding | msg.Request:

		if this.auth == nil {
			log.Println("Binding to address:", ip, port)
 			res := msg.NewResponse(msg.Success|msg.Binding, req)
			xorAddr := msg.NewXORAddress(ip, port, res.Header())
			res.AddAttribute(xorAddr)
			
			log.Println("Responding\n\n", res)
			conn.Write(res.EncodeMessage())

			this.conns <- &Connection{req, conn}
			return
		} 

		integrity, iErr := req.Attribute(msg.MessageIntegrity)
		user, uErr := req.Attribute(msg.Username)
		_, rErr := req.Attribute(msg.Realm)
		nonce, nErr := req.Attribute(msg.Nonce)
		
		if iErr != nil {
			// Reject request
			res := msg.NewResponse(msg.Error, req)
			e, _ := msg.NewErrorAttr(msg.Unauthorized, "Unauthorized")
			res.AddAttribute(e)
			
			// TODO: provide a better realm name
			r, _ := msg.NewRealm(Realm)
			res.AddAttribute(r)
			
			n := msg.NewNonce()
			res.AddAttribute(n)
		
			log.Println("No Integrity\n\n", res)
			conn.Write(res.EncodeMessage())

		} else if uErr != nil || rErr != nil || nErr != nil {
			// Reject request
			res := msg.NewResponse(msg.Error, req)
			e, _ := msg.NewErrorAttr(msg.BadRequest, "Bad Request")
			res.AddAttribute(e)
			
			log.Println("Missing user, nonce, or realm\n\n", res)
			conn.Write(res.EncodeMessage())

		} else if !msg.ToNonce(nonce).Valid() {
			// Reject request
			res := msg.NewResponse(msg.Error, req)
			e, _ := msg.NewErrorAttr(msg.StaleNonce, "Stale Nonce")
			res.AddAttribute(e)
			
			// TODO: provide a better realm name
			r, _ := msg.NewRealm(Realm)
			res.AddAttribute(r)
			
			n := msg.NewNonce()
			res.AddAttribute(n)
			
			log.Println("Invalide Nonce\n\n", res)
			conn.Write(res.EncodeMessage())

		} else if passwd, ok := this.auth.Password(string(user.Value())); ok {
			username := string(user.Value())

			if !msg.ToIntegrity(integrity).Valid(username, passwd, Realm, req) {
				res := msg.NewResponse(msg.Error, req)
				e, _ := msg.NewErrorAttr(msg.Unauthorized, "Unauthorized")
				res.AddAttribute(e)
				
				// TODO: provide a better realm name
				r, _ := msg.NewRealm(Realm)
				res.AddAttribute(r)
				
				n := msg.NewNonce()
				res.AddAttribute(n)
				
				log.Println("Invalid integrity \n\n", res)
				conn.Write(res.EncodeMessage())
				
			} else {
				res := msg.NewResponse(msg.Success|msg.Binding, req)
				xorAddr := msg.NewXORAddress(ip, port, res.Header())
				res.AddAttribute(xorAddr)
				
				integrity := msg.NewIntegrityAttr(username, passwd, Realm, req)
				res.AddAttribute(integrity)
				
				log.Println("Responding\n\n", res)
				conn.Write(res.EncodeMessage())
				
				this.conns <- &Connection{req, conn}
			}
		} else {
			// Reject request
			res := msg.NewResponse(msg.Error, req)
			e, _ := msg.NewErrorAttr(msg.Unauthorized, "User Not Found")
			res.AddAttribute(e)
			
			// TODO: provide a better realm name
			r, _ := msg.NewRealm(Realm)
			res.AddAttribute(r)
			
			n := msg.NewNonce()
			res.AddAttribute(n)
		
			log.Println("User Not Found\n\n", res)
			conn.Write(res.EncodeMessage())

		}


	
	default: // Unrecognized messages
		this.conns <- &Connection{req, conn}
	}

}
