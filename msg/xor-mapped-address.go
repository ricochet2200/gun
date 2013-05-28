package msg

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
)

const XORMappedAddress TLVType = 0x0020
func init() {

	x := func(t TLVType, b []byte) TLV { return &XORAddress{NewTLV(t, b)} }
	RegisterAttributeType(XORMappedAddress, "XOR Mapped Address", x)
}

type XORAddress struct {
	TLV
}

func NewXORAddress(ip net.IP, port int, h *Header) *XORAddress {
	return &XORAddress{&TLVBase{XORMappedAddress, XORAddrBytes(ip, port, h)}}
}

func XORAddrBytes(ip net.IP, port int, header *Header) []byte {

	xip := make([]byte, 16)

	// RFC 5389
	// 0x01:IPv4
	// 0x02:IPv6
	family := []byte{0, 1}

	for i := 0; i < net.IPv4len; i++ {
		xip[i] = ip[i] ^ MagicCookie[i]
	}

	if ip.To4() == nil {
		log.Println("IPV6 Address found", ip)
		for i := 4; i < 16; i++ {
			xip[i] = ip[i] ^ header.id[i-4]
		}
		family[1] = 2
	}

	xport := []byte{0, 0}
	binary.BigEndian.PutUint16(xport, uint16(port))
	for i := 0; i < 2; i++ {
		xport[i] = xport[i] ^ MagicCookie[i]
	}

	value := family
	value = append(value, xport...)
	value = append(value, xip...)
	return value
}

func DecodeIP(family byte, ip []byte, header *Header) net.IP {

	for i := 0; i < 4; i++ {
		ip[i] = ip[i] ^ MagicCookie[i]
	}

	if family == 2 {
		for i := 4; i < 16; i++ {
			ip[i] = ip[i] ^ header.id[i-4]
		}
	}

	return ip
}

func (this *XORAddress) IP(header *Header) net.IP {
	v := this.Value()
	return DecodeIP(v[2], v[4:], header)
}

func DecodePort(p []byte) []byte {
	for i := 0; i < 2; i++ {
		p[i] = p[i] ^ MagicCookie[i]
	}
	return p
}

func (this *XORAddress) PortByteArray() []byte {
	return DecodePort(this.Value()[2:4])
}

func (this *XORAddress) Port() int {
	p := this.PortByteArray()

	var port uint16 = 0
	binary.Read(bytes.NewBuffer(p), binary.BigEndian, &port)
	return int(port)
}
