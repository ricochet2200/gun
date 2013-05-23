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

// See page 10 of RFC 5389
const (
	//Classes
	Request    MessageType = 0x0000
	Indication MessageType = 0x0010
	Success    MessageType = 0x0100
	Error      MessageType = 0x0110

	// Methods
	Binding MessageType = 0x0001
)

const MethodMask MessageType = 0x3EEF
const ClassMask MessageType = 0x0110

var methodTypeToString map[MessageType]string = make(map[MessageType]string)
var classTypeToString map[MessageType]string = make(map[MessageType]string)

func init() {
	RegisterMethodType(Binding, "Binding")
	classTypeToString[Request] = "Request"
	classTypeToString[Indication] = "Indication"
	classTypeToString[Success] = "Success"
	classTypeToString[Error] = "Error"
}

func RegisterMethodType(t MessageType, prettyName string) {

	if t & ClassMask > 0 {
		panic("Invalid method number, see rfc 5389 for details")
	}

	if _, contains := methodTypeToString[t]; contains {
		panic("Message Type already registered")
	}

	methodTypeToString[t] = prettyName
}

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

func (this *Header) TypeString() string {
	ret := ""
	if v, contains := classTypeToString[this.msgType & ClassMask]; contains {
		ret += v + " "
	} else {
		panic("Message type has no class")
	}

	if v, contains := methodTypeToString[this.msgType & MethodMask]; contains {
		ret += v
	} else {
		panic("Message type has no method")
	}

	return ret
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

	ret := "Header:\ntype: " + this.TypeString()
	ret += "\nlength: " + strconv.Itoa(int(this.length))
	ret += "\nid: "
	for i := 0; i < len(this.id); i += 4 {

		var id int32 = 0
		binary.Read(bytes.NewBuffer(this.id[i:i+4]), binary.BigEndian, &id)
		ret += strconv.Itoa(int(id))
	}

	return ret

}
