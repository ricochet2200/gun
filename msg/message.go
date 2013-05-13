package msg

import (
	"errors"
	"io"
	"log"
)

type Message struct {
	header *Header
	attr   []TLV
}

func NewRequest(msgType MessageType) *Message {
	return &Message{NewHeader(msgType, 0), []TLV{}}
}

func NewResponse(msgType MessageType, req *Message) *Message {
	header := &Header{msgType, 0, req.header.id}
	return &Message{header, []TLV{}}
}

func DecodeMessage(conn io.Reader) (*Message, error) {
	header, err := DecodeHeader(conn)
	if err != nil {
		return nil, err
	}
	tvl := []TLV{}
	for i := uint16(0); i < header.length; {
		if t, err := Decode(conn); err == nil {
			tvl = append(tvl, t)
			i += t.Length()
		}
	}

	return &Message{header, tvl}, err
}

func (this *Message) EncodeMessage() []byte {
	ret := this.header.Data()
	for _, a := range this.attr {
		ret = append(ret, a.Encode()...)
	}
	return ret
}

func (this *Message) Type() MessageType {
	log.Println(this.header)
	return this.header.msgType
}

func (this *Message) Header() *Header {
	return this.header
}

func (this *Message) AddAttribute(tlv TLV) {
	this.attr = append(this.attr, tlv)
	this.header.length += tlv.Length()
}

func (this *Message) Attribute(t TLVType) (TLV, error) {
	for _, a := range this.attr {
		if a.Type() == t {
			return a, nil
		}
	}
	return nil, errors.New("Message not found")
}

func (this *Message) String() string {
	ret := this.header.String()
	for _, a := range this.attr {
		ret += "\n" + a.String()
	}
	return ret
}
