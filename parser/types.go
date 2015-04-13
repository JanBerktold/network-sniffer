package main

type ProtocolHeader interface {
	GetProtocol() uint8
}

type EthernetHeader struct {
	Destination, Source []byte
	Type                uint16
	//FCS                 int32
}

type IPv4Header struct {
	Version        byte
	HeaderLength   byte
	TypeOfService  int8
	TotalLength    uint16
	Identification uint16
	ForbidFragment bool
	MoreFragments  bool
	FragmentOffset byte // 13
	TimeToLive     uint8
	Protocol       uint8
	HeaderChecksum uint16
	Source         uint32
	Destination    uint32
}

type UDPHeader struct {
	NextHeader uint8
}

func (v IPv4Header) GetProtocol() uint8 {
	return v.Protocol
}
