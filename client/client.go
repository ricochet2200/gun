package client

import (
	"github.com/ricochet2200/gun/msg"
	"errors"
	"log"
	"net"
)

type Client struct {
	server string
	maxOutstandingTransactions int
	username string
	password string 	//TODO: SASLPrep the password
}

func NewClient(server, user, passwd string) *Client {
	return &Client{server, 10, user, passwd}
}

// Sends a request where you expect to get a response back
func (this *Client) SendReqRes(req *msg.Message) (*Connection, error) {

	conn, err := net.Dial("tcp", this.server)
	if err != nil {
		log.Println("Failed to create connection: ", err)
		return nil, err
	}

	this.maxOutstandingTransactions += 1

	log.Println(req)
	conn.Write(req.EncodeMessage())
	
	res, err := msg.DecodeMessage(conn)
	this.maxOutstandingTransactions -= 1

	if err != nil {
		conn.Close()
		return nil, err
	} 

	log.Println("Message recieved\n", res)

	if attr, err := res.Attribute(msg.ErrorCode); err == nil {
		if code, err := msg.Code(attr); err == nil{
			log.Println("error code", code)			
			switch(code) {

			case msg.StaleNonce :
				log.Println("Stale Nonce, calling authenticate...")
				conn.Close()
				return this.Authenticate(res)

			case msg.Unauthorized :
				log.Println("unauthorized")

				if _, err := req.Attribute(msg.MessageIntegrity); err == nil {
					conn.Close() // We already tried once...
					return nil, errors.New("Invalid credentials")
				} else {
					conn.Close()
					return this.Authenticate(res)
				}

			case msg.BadRequest:
					conn.Close()
					return nil, errors.New("Client error. Bad Request")
			}
		}
	}
	
	return &Connection{res, conn}, nil
}

func (this *Client) Bind() (net.IP, int, error) {

	log.Println("Binding...")
	req := msg.NewRequest(msg.Request | msg.Binding)
	c, err := this.SendReqRes(req)
	if err != nil {
		return nil, -1, err
	} 

	return ToIPPort(c)
}	

func ToIPPort(conn *Connection) (net.IP, int, error) {

	tlv, err := conn.msg.Attribute(msg.XORMappedAddress)
	if err != nil {
		return nil, -1, err
	} 
	
	xorAddr, err := msg.ToXORAddress(tlv, conn.msg.Header())
	if err != nil {
		log.Println("Error: Malformed response by the server")
		return nil, -1, errors.New("Malformed response by server")
	}
	
	log.Println("Good message recieved")
	return xorAddr.IP(), xorAddr.Port(), nil
}


func (this *Client) Authenticate(res *msg.Message) (*Connection, error) {

	req := msg.NewRequest(msg.Request | msg.Binding)
	user, err := msg.NewUser(this.username)
	if err != nil {
		return nil, err
	}

	req.AddAttribute(user)

	r, _ := res.Attribute(msg.Realm)
	realm := string(r.Value())
	req.AddAttribute(r)
	

	nounce, _ := res.Attribute(msg.Nonce)
	req.AddAttribute(nounce)

	integrity := msg.NewIntegrityAttr(this.username, this.password, realm, req)
	req.AddAttribute(integrity)

	return this.SendReqRes(req)
}