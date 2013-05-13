package client

import (
	"../msg"
	"errors"
	"log"
	"net"
	"time"
)

type Client struct {
	server                     string
	rm                         int // Default 16
	rcDefault                  int // Retransmission Count. Default 7
	rto                        int // ms.  Retransmission TimeOut. See RCF 2988 for default.
	maxOutstandingTransactions int
}

func NewClient(server string) *Client {
	return &Client{server, 16, 7, 500, 10}
}

func (this *Client) ConnectTCP() (net.IP, int, error) {
	conn, err := net.Dial("tcp", this.server)
	if err != nil {
		log.Println("Failed to create connection: ", err)
		return nil, -1, err
	}
	return this.Bind(conn)
}

func (this *Client) ConnectUDP() (net.IP, int, error) {

	conn, err := net.Dial("udp", this.server)
	if err != nil {
		log.Println("Failed to create connection: ", err)
		return nil, -1, err
	}
	return this.Bind(conn)
}

func (this *Client) Bind(conn net.Conn) (net.IP, int, error) {

	response := make(chan *msg.Message)

	go func(response chan *msg.Message) {
		for {
			if msg, err := msg.DecodeMessage(conn); err != nil {
				log.Println(err)
			} else {
				response <- msg
			}
		}
	}(response)

	req := msg.NewRequest(msg.Request | msg.Binding).EncodeMessage()
	log.Println("Connecting to STUN Server")
	conn.Write(req)

	rc := 1
	rcDefault := this.rcDefault
	tmpRto := this.rto
	rto := time.After(time.Duration(this.rto) * time.Millisecond)
	res := (*msg.Message)(nil)

	for {
		select {
		case <-rto:
			rc++
			if rc < rcDefault {
				tmpRto = tmpRto*2 + this.rto
			} else if rc == rcDefault {
				tmpRto = tmpRto + this.rto*this.rm
			} else {
				log.Println("Server timed out")
				return nil, -1, errors.New("Server timed out")
			}

			rto = time.After(time.Duration(tmpRto) * time.Millisecond)
			log.Println("Trying again in..", tmpRto, "ms")

			conn.Write(req)

		case res = <-response:
			log.Println("recieved a response")
			this.rto = tmpRto
			if tlv, err := res.Attribute(msg.XORMappedAddress); err != nil {
				log.Println("Unusable message response")
			} else {
				xorAddr, err := msg.ToXORAddress(tlv, res.Header())
				if err != nil {
					log.Println("Error: Malformed response by the server")
					return nil, -1, errors.New("Malformed response by server")
				}

				log.Println("Good message recieved")
				return xorAddr.IP(), xorAddr.Port(), nil
			}
		}
	}

	return nil, -1, nil // This will never happen
}
