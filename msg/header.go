package msg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"strconv"
)

type MessageType uint16

const (
	//Classes
	Request    MessageType = 0x0b00
	Indication MessageType = 0x0b01
	Success    MessageType = 0x0b01
	Error      MessageType = 0x0b11

	// Methods
	Binding MessageType = 0x0001
)

var MagicCookie = []byte{33, 18, 164, 66}

type Header struct {
	msgType MessageType
	length  uint16 // size of msg in bytes, not including header
	// MagicCookie
	id []byte
}

func NewHeader(msgType MessageType, length uint16) *Header {
	id := make([]byte, 3*4)
	for i := 0; i < 3; i++ {
		binary.BigEndian.PutUint32(id[i*4:(i+1)*4], uint32(rand.Int31()))
	}

	return &Header{msgType, length, id}
}

func DecodeHeader(conn io.Reader) (*Header, error) {

	buf, err := Read(conn, 20)
	if err != nil {
		return nil, err
	}

	// Make sure magic cookie is in the right place
	if buf[4] == MagicCookie[0] && buf[5] == MagicCookie[1] &&
		buf[6] == MagicCookie[2] && buf[7] == MagicCookie[3] {

		var msgType uint16 = 0
		err := binary.Read(bytes.NewBuffer(buf[0:2]), binary.BigEndian, &msgType)
		if err != nil {
			return nil, err
		}

		var length uint16 = 0
		err = binary.Read(bytes.NewBuffer(buf[2:4]), binary.BigEndian, &length)
		if err != nil {
			return nil, err
		}

		header := &Header{MessageType(msgType), length, buf[8:20]}

		// Check that first to bits are 0s
		if header.msgType > 16383 {

			return nil, errors.New("Bad message type")
		}

		if header.length%4 != 0 {
			return nil, errors.New("Message length not a multiple of 4")
		}

		return header, nil

	} else {
		log.Println(buf, MagicCookie)
		return nil, errors.New("Magic cookie is inedible")
	}

	log.Println("Go 1.1 makes it so I don't have to do this")
	return nil, nil
}

func (this *Header) Type() MessageType {
	return this.msgType
}

func (this *Header) Copy() *Header {
	return &Header{this.msgType, this.length, this.id}
}

func (this *Header) SetLength(length uint16) {
	this.length = length
}

func (this *Header) TransactionId() []byte {
	return this.id
}

func (this *Header) Data() []byte {

	ret := make([]byte, 0, 20)

	msg := []byte{0, 0}
	binary.BigEndian.PutUint16(msg, uint16(this.msgType))
	ret = append(ret, msg...)

	l := []byte{0, 0}
	binary.BigEndian.PutUint16(l, this.length)
	ret = append(ret, l...)

	ret = append(ret, MagicCookie...)
	ret = append(ret, this.id...)

	return ret
}

func (this *Header) String() string {

	ret := "Header:\ntype: " + strconv.Itoa(int(this.msgType))
	ret += "\nlength: " + strconv.Itoa(int(this.length))
	ret += "\nid: "
	for i := 0; i < len(this.id); i += 4 {

		var id int32 = 0
		binary.Read(bytes.NewBuffer(this.id[i:i+4]), binary.BigEndian, &id)
		ret += strconv.Itoa(int(id))
	}

	return ret

}
