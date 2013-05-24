package msg

import (
	"bytes"
	"encoding/binary"
	"io"
//	"strconv"
	"errors"
	"log"
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
const ErrorCode TLVType = 0x0009
const UnknownTLVTypes TLVType = 0x000A

// Comprehension-optional range (0x8000-0xFFFF)
const Software TLVType = 0x8022
const AlternateServer TLVType = 0x8023
const FingerPrint TLVType = 0x8028

var tlvTypeToString map[TLVType]string = make(map[TLVType]string)
var tlvTypeToFunc map[TLVType]func(TLVType, []byte) TLV = make(map[TLVType]func(TLVType, []byte) TLV)

func init() {

	f := func(t TLVType, b []byte) TLV{return &TLVBase{t, b}}

	RegisterAttributeType(MappedAddress, "Mapped Address", f)
	RegisterAttributeType(ErrorCode, "Error Code", f)
	RegisterAttributeType(UnknownTLVTypes, "Unknown Type", f)
	RegisterAttributeType(AlternateServer, "Alternative Server", f)
	RegisterAttributeType(FingerPrint, "Finger Print", f)
}

func RegisterAttributeType(t TLVType, name string, f func(TLVType,[]byte) TLV) {
	if _, contains := tlvTypeToString[t]; contains {
		panic("TLV Type already registered")
	}

	tlvTypeToString[t] = name
	tlvTypeToFunc[t] = f
}

// No need to register these because they are context specific
type StunErrorCode int16
const TryAlternative StunErrorCode = 300
const BadRequest StunErrorCode = 400
const Unauthorized StunErrorCode = 401
const UnknownAttribute StunErrorCode = 420
const StaleNonce StunErrorCode = 438
const ServerError StunErrorCode = 500

type TLV interface {
	Type() TLVType
	TypeString() string
	Value() []byte
	ValueToString() string
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

func NewTLV(t TLVType, v []byte) *TLVBase{
	return &TLVBase{t, v}
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
	return append(ret, v...)
}

func Decode(in io.Reader) (TLV, int, error) {

	buf, err := Read(in, 4)
	if err != nil {
		log.Println("TLV missing header", err)
		return nil, 0, err
	}

	var t TLVType = 0
	err = binary.Read(bytes.NewBuffer(buf[0:2]), binary.BigEndian, &t)
	if err != nil {
		return nil, 0, err
	}
	
	var length uint16 = 0
	err = binary.Read(bytes.NewBuffer(buf[2:4]), binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}

	v, err := Read(in, int(length))
	if err != nil {
		return nil, 0, err
	}

	padding := int(length % 4)
	Read(in, padding)

	attr := tlvTypeToFunc[t](t, v)
	return attr, padding, nil
}

func (this *TLVBase) Type() TLVType {
	return this.attrType
}

func (this *TLVBase) TypeString() string {
	v, ok := tlvTypeToString[this.Type()]
	if ok {
		return v
	}
	panic("Unregistered type")
}

func (this *TLVBase) Length() uint16 {
	return uint16(len(this.Value()))
}

func (this *TLVBase) Value() []byte {
	return this.value
}

func (this *TLVBase) ValueToString() string {
	return string(this.Value())
}

func (this *TLVBase) String() string {
	return this.TypeString()
}

type StunError struct {
	TLV
}

func NewErrorAttr(code StunErrorCode, msg string) (*StunError, error) {

	class := code / 100
	if class < 3 || class > 6 {
		return nil, errors.New("Invalid error code. Valid code:299 < code < 700")
	}
	
	if len(msg) > 128 {
		return nil, errors.New("Message needs to be under 128 characters")
	}

	v := []byte{0,0, byte(class), byte(code % 100) }
	v = append(v, []byte(msg)...)

	return &StunError{&TLVBase{ErrorCode, v}}, nil
}

func (this *StunError) String() string {
	return string(this.Value()[4:])
}

func Code(t TLV) (StunErrorCode, error) {

	buf := t.Value()
	var family uint8 = 0
	err := binary.Read(bytes.NewBuffer(buf[2:3]), binary.BigEndian, &family)
	if err != nil {
		return 0, err
	}

	var code uint8 = 0
	err = binary.Read(bytes.NewBuffer(buf[3:4]), binary.BigEndian, &code)
	if err != nil {
		return 0, err
	}

	return StunErrorCode(family) * 100 + StunErrorCode(code), nil
}