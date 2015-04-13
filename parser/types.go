package main

type EthernetHeader struct {
	Destination, Source []byte
	Type                uint16
	//FCS                 int32
}

type IPHeader struct {
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
