package msg

import (
	"errors"
	"time"
	"encoding/binary"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"bytes"
	"log"
)

const Username TLVType = 0x0006
const MessageIntegrity TLVType = 0x0008

const Realm TLVType = 0x0014
const Nonce TLVType = 0x0015

func init() {
	u := func(t TLVType, b []byte) TLV { return &UserAttr{NewTLV(t, b)} }
	m := func(t TLVType, b []byte) TLV { return &IntegrityAttr{NewTLV(t, b)} }
	r := func(t TLVType, b []byte) TLV { return &RealmAttr{NewTLV(t, b)} }
	n := func(t TLVType, b []byte) TLV { return &NonceAttr{NewTLV(t, b)} }

	RegisterAttributeType(Username, "Username", u)
	RegisterAttributeType(MessageIntegrity, "Message Integrity", m)
	RegisterAttributeType(Realm, "Realm", r)
	RegisterAttributeType(Nonce, "Nonce", n)
}

type RealmAttr struct {
	TLV
}

func NewRealm(realm string) (*RealmAttr, error) {

	// TODO: Properly process the realm string
	if len(realm) > 127 {
		return nil, errors.New("realm must be under 128 characters")
	}

	return &RealmAttr{&TLVBase{Realm, []byte(realm)}}, nil
}

func (this *RealmAttr) String() string {
	return string(this.Value())
}

type NonceAttr struct {
	TLV
}

func NewNonce() (*NonceAttr) {
	// TODO: Pick a better nonce
	expires := time.Now().Add(time.Duration(1) * time.Minute)
	return &NonceAttr{&TLVBase{Nonce, TimeToBytes(expires)}}
}

func (this *NonceAttr) String() string {
	var ret int64 = 0
	err := binary.Read(bytes.NewBuffer(this.Value()), binary.BigEndian, &ret)
	if err != nil {
		return "Error"
	}
	
	return time.Unix(ret, 0).String()
}

func ValidNonce(t TLV) bool {

	var ret int64 = 0
	err := binary.Read(bytes.NewBuffer(t.Value()), binary.BigEndian, &ret)
	if err != nil {
		return false
	}

	return time.Unix(ret, 0).After(time.Now())
}

type UserAttr struct {
	TLV
}

func NewUser(username string) (*UserAttr, error) {
	
	// TODO: clean username with SASLPrep
	if len(username) > 512 {
		return nil, errors.New("User name must be less than 512 bytes")
	}

	return &UserAttr{&TLVBase{Username, []byte(username)}}, nil
}

func (this *UserAttr) User () string {
	return this.ValueToString()
}

func (this *UserAttr) String () string {
	return this.ValueToString()
}

type IntegrityAttr struct {
	TLV
}

func ToIntegrity(t TLV) *IntegrityAttr {
	return &IntegrityAttr{t}
}

func NewIntegrityAttr(user, passwd, realm string, msg *Message) *IntegrityAttr {
	
	data := CreateHMAC( user, passwd, realm, msg)
	
	return ToIntegrity(&TLVBase{MessageIntegrity, data})
}

func (this *IntegrityAttr) Valid(user, passwd, realm string, msg *Message) bool {

	i, err := msg.Attribute(MessageIntegrity)
	if err != nil {
		log.Println("No integrity")
		return true
	}

	h2 := CreateHMAC(user, passwd, realm, msg)
	if err != nil {
		return false 
	}

	h1 := i.Value()
	return len(h1) == len(h2) && subtle.ConstantTimeCompare(h1, h2) == 1
}

func CreateHMAC (user, passwd, realm string, msg *Message) []byte {

 	hash := md5.New()
	key := user + ":" + realm + ":" + passwd
	io.WriteString(hash, key)

	mac := hmac.New(sha256.New, hash.Sum(nil))
	mac.Write(IntegrityCopy(msg).EncodeMessage())
	sum := mac.Sum(nil)

	return sum
}

func IntegrityCopy (orig *Message) *Message {

	attrs := orig.attr
	for i := 0; i < len(attrs); i++ {
		if attrs[i].Type() == FingerPrint || attrs[i].Type() == MessageIntegrity {
			attrs = append(attrs[:i], attrs[i+1:]...)
		}	
	}

	header := orig.Header().Copy()
	header.length = 0
	ret := &Message{header, []TLV{}}
	for _, a := range attrs {
		ret.AddAttribute(a)
	}
	
	return ret
}