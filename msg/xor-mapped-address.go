package msg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
)

const XORMappedAddress TLVType = 0x0020

type XORAddress struct {
	TLV
	header *Header
}

func ToXORAddress(tlv TLV, header *Header) (*XORAddress, error) {
	if tlv.Type() == XORMappedAddress {
		return &XORAddress{tlv, header}, nil
	}
	return nil, errors.New("This is not an XORAddress message")
}

func NewXORAddress(ip net.IP, port int, header *Header) *XORAddress {

	xip := []byte{0,0,4,0}
	xport := []byte{0, 0}
	binary.BigEndian.PutUint16(xport, uint16(port))

	nip := ip.To4()
	if nip == nil {
		log.Println("Unsupported ip type", ip)
		nip = ip
	}

	// TODO: Make IPV6 work
	//	isV4 := ip.To4() != nil

	for i := 0; i < net.IPv4len; i++ {
		xip[i] = nip[i] ^ MagicCookie[i]
	}

	/*	if !isV4 {
		log.Println("IPV6 Address found", ip)
		for i := 4; i < 16; i++ {
			log.Println(header.id, len(header.id), i)
			ip[i] = ip[i] ^ header.id[i-4]
		}
	}*/

	for i := 0; i < 2; i++ {
		xport[i] = xport[i] ^ MagicCookie[i]
	}

	value := []byte{0, 1} // TODO: Add Family correctly
	value = append(value, xport...)
	value = append(value, xip...)

	return &XORAddress{&TLVBase{XORMappedAddress, value}, header}
}

func IP(t TLV) net.IP {

	v := t.Value()[4:]
	for i := 0; i < 4; i++ {
		v[i] = v[i] ^ MagicCookie[i]
	}

	// TODO: Make IPV6 work	
	/*if this.Length() == 20 {
		for i := 4; i < 16; i++ {
			v[i] = v[i] ^ this.header.id[i-4]
		}
	}*/
	return v
}

func Port(t TLV) int {
	p := t.Value()[2:4]
	for i := 0; i < 2; i++ {
		p[i] = p[i] ^ MagicCookie[i]
	}

	var port uint16 = 0
	binary.Read(bytes.NewBuffer(p), binary.BigEndian, &port)
	return int(port)
}
