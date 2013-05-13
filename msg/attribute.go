package msg

import (
	"bytes"
	"encoding/binary"
	"io"
	"strconv"

//	"log"
)

/*Comprehension-required range (0x0000-0x7FFF):
0x0000: (Reserved)
0x0001: MAPPED-ADDRESS
0x0002: (Reserved; was RESPONSE-ADDRESS)
0x0003: (Reserved; was CHANGE-ADDRESS)
0x0004: (Reserved; was SOURCE-ADDRESS)
0x0005: (Reserved; was CHANGED-ADDRESS)
0x0006: USERNAME
0x0007: (Reserved; was PASSWORD)
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: (Reserved; was REFLECTED-FROM)
0x0014: REALM
0x0015: NONCE
0x0020: XOR-MAPPED-ADDRESS

Comprehension-optional range (0x8000-0xFFFF)
0x8022: SOFTWARE
0x8023: ALTERNATE-SERVER
0x8028: FINGERPRINT
*/

type TLVType uint16

// Comprehension-required range (0x0000-0x7FFF):
const MappedAddress TLVType = 0x0001
const Username TLVType = 0x0006
const MessageIntegrety TLVType = 0x0008
const ErrorCode TLVType = 0x0009
const UnknownTLVTypes TLVType = 0x000A
const Realm TLVType = 0x0014
const Nonce TLVType = 0x0015

// Comprehension-optional range (0x8000-0xFFFF)
const Software TLVType = 0x8022
const AlternateServer TLVType = 0x8023
const FingerPrint TLVType = 0x8028

type TLV interface {
	Type() TLVType
	Value() []byte
	Length() uint16
	Encode() []byte
	String() string
}

// Type, Length, Value
// 0x0000 and 0x7FFF required. Fail if not known
// 0x8000 and 0xFFFF optional. Ignore if not known
type TLVBase struct {
	attrType TLVType
	value    []byte
}

func (this *TLVBase) Encode() []byte {

	ret := make([]byte, 0, this.Length())
	t := []byte{0, 0}
	binary.BigEndian.PutUint16(t, uint16(this.Type()))
	ret = append(ret, t...)

	l := []byte{0, 0}
	binary.BigEndian.PutUint16(l, uint16(this.Length()))
	ret = append(ret, l...)

	v := this.Value()
	paddingLen := this.Length() % 4
	v = append(v, make([]byte, paddingLen)...)
	return append(ret, this.Value()...)
}

func Decode(in io.Reader) (TLV, error) {

	buf, err := Read(in, 4)
	if err != nil {
		return nil, err
	}

	var t uint16 = 0
	err = binary.Read(bytes.NewBuffer(buf[0:2]), binary.BigEndian, &t)
	if err != nil {
		return nil, err
	}

	var length uint16 = 0
	err = binary.Read(bytes.NewBuffer(buf[2:4]), binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	v, err := Read(in, int(length))
	if err != nil {
		return nil, err
	}

	padding := int(length % 4)
	Read(in, padding)

	return &TLVBase{TLVType(t), v}, nil
}

func (this *TLVBase) Type() TLVType {
	return this.attrType
}

func (this *TLVBase) Length() uint16 {
	return uint16(len(this.Value()))
}

func (this *TLVBase) Value() []byte {
	return this.value
}

func (this *TLVBase) String() string {
	ret := "TLVBase:\nAttribute Type: " + strconv.Itoa(int(this.Type()))
	ret += "\nLength: " + strconv.Itoa(int(this.Length()))
	return ret // "\nvalue: " + string(this.Value())
}
