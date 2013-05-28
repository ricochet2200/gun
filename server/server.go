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
	realm *msg.RealmAttr
}

func NewServer(port int, c chan *Connection, a Authenticator) *Server {
	
	r, e := msg.NewRealm(Realm)
	if e != nil {
		panic(e)
	}
	return &Server{port, c, a, r}
}

func (this *Server) Start() error {

	log.Println("Listening on ", ":"+strconv.Itoa(this.port) )
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
		ip := raddr.(*net.TCPAddr).IP
		port := raddr.(*net.TCPAddr).Port
		go this.handleConnection(conn, ip, port)
	}
	return nil
}

func (this *Server) handleConnection(out net.Conn, ip net.IP, port int) {

	req, err := msg.DecodeMessage(out)
	if err != nil {
		log.Println(err)
		return
	}

	conn := &Connection{Req: req, Out: out, Realm: Realm}

	switch req.Type() {
	case msg.Binding | msg.Request:

		if this.auth == nil {
			log.Println("Binding to address:", ip, port)
 			res := msg.NewResponse(msg.Success, req)
			xorAddr := msg.NewXORAddress(ip, port, res.Header())
			res.AddAttribute(xorAddr)
			
			out.Write(res.EncodeMessage())

			this.conns <- conn
			return
		} 

		if this.Validate(conn) {
			conn.Write(msg.NewResponse(msg.Success, req))
			this.conns <- conn
		}

	default: // Unrecognized messages
		this.conns <- conn
	}
}

// If the request is not valid this function sends a proper message back to the
// client.  Updates user, passwd, and realm fields in conn.  Not all fields are
// guaranteed to be correct unless Validate() return true
func (this *Server) Validate(conn *Connection) bool {

	req := conn.Req
	
	// Request attributes
	integrity, iErr := req.Attribute(msg.MessageIntegrity)
	user, uErr := req.Attribute(msg.Username)
	_, rErr := req.Attribute(msg.Realm)
	nonce, nErr := req.Attribute(msg.Nonce)
	ok := false

	// Response attributes
	res := msg.NewResponse(msg.Error, req)
	n := msg.NewNonce()

	if uErr == nil {
		conn.User = user.(*msg.UserAttr).String()
		conn.Passwd, ok = this.auth.Password(conn.User)
		if ok {
			conn.HasAuth = true
		}
	}
	
	if iErr != nil {
		// Reject request
		e, _ := msg.NewErrorAttr(msg.Unauthorized, "Unauthorized")
		res.AddAttribute(e)
		res.AddAttribute(this.realm)
		res.AddAttribute(n)
		
		log.Println("No Integrity")
		conn.Write(res)
		return false

	} else if uErr != nil || rErr != nil || nErr != nil {
		// Reject request
		e, _ := msg.NewErrorAttr(msg.BadRequest, "Bad Request")
		res.AddAttribute(e)
		
		log.Println("Missing user, nonce, or realm")
		conn.Write(res)
		return false

	} else if !ok {
		// Reject request
		res := msg.NewResponse(msg.Error, req)
		e, _ := msg.NewErrorAttr(msg.Unauthorized, "User Not Found")
		res.AddAttribute(e)
		res.AddAttribute(this.realm)
		res.AddAttribute(n)
		
		log.Println("User Not Found")
		conn.Write(res)	
		return false

	} else if !msg.ValidNonce(nonce) {
		// Reject request
		e, _ := msg.NewErrorAttr(msg.StaleNonce, "Stale Nonce")
		res.AddAttribute(e)
		res.AddAttribute(this.realm)
		res.AddAttribute(n)
		
		log.Println("Invalid Nonce")
		conn.Write(res)
		return false
		
	} else if !msg.ToIntegrity(integrity).Valid(conn.User, conn.Passwd, Realm, req) {

		e, _ := msg.NewErrorAttr(msg.Unauthorized, "Unauthorized")
		res.AddAttribute(e)
		res.AddAttribute(this.realm)
		res.AddAttribute(n)
		
		log.Println("Invalid integrity")
		conn.Write(res)
		return false
	}

	return true
}
