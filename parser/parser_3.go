package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

type Level3 interface{}
type Parse3Function func(io.Reader) ProtocolHeader

var (
	parser3 = map[uint16]Parse3Function{
		2048: ParseIPv4,
		6:    ParseIPv6,
	}
)

func ReadByte(rd io.Reader) byte {
	r := bufio.NewReader(rd)
	b, _ := r.ReadByte()
	return b
}

func ParseIPv4(rd io.Reader) ProtocolHeader {
	ipHead := IPv4Header{}

	firstByte := ReadByte(rd)

	ipHead.Version = firstByte >> 4
	ipHead.HeaderLength = firstByte & 0x0F

	binary.Read(rd, binary.BigEndian, &ipHead.TypeOfService)
	binary.Read(rd, binary.BigEndian, &ipHead.TotalLength)
	binary.Read(rd, binary.BigEndian, &ipHead.Identification)

	fragmentByte1 := ReadByte(rd)
	ReadByte(rd) // second byte used for FragmentOffset

	notFragment := fragmentByte1 >> 5
	moreFragment := fragmentByte1 >> 6

	ipHead.ForbidFragment = notFragment == 1
	ipHead.MoreFragments = moreFragment == 1

	binary.Read(rd, binary.BigEndian, &ipHead.TimeToLive)
	binary.Read(rd, binary.BigEndian, &ipHead.Protocol)
	binary.Read(rd, binary.BigEndian, &ipHead.HeaderChecksum)
	binary.Read(rd, binary.BigEndian, &ipHead.Source)
	binary.Read(rd, binary.BigEndian, &ipHead.Destination)

	if verbose {
		fmt.Printf("\t\t-- Layer 3 :: IP Header --\n")
		fmt.Printf("\t\t\tVersion: %v\n", ipHead.Version)
		fmt.Printf("\t\t\tHeader Length: %v\n", ipHead.HeaderLength)
		fmt.Printf("\t\t\tType of Service: %v\n", ipHead.TypeOfService)
		fmt.Printf("\t\t\tTotal Length: %v\n", ipHead.TotalLength)
		fmt.Printf("\t\t\tIdentification: %v\n", ipHead.Identification)
		fmt.Printf("\t\t\tForbid Fragment %v\n", ipHead.ForbidFragment)
		fmt.Printf("\t\t\tMore Fragments %v\n", ipHead.MoreFragments)
		fmt.Printf("\t\t\tTime to live: %v\n", ipHead.TimeToLive)
		fmt.Printf("\t\t\tProtocol: %v\n", ipHead.Protocol)
		fmt.Printf("\t\t\tHeader Checksum: %v\n", ipHead.HeaderChecksum)
		fmt.Printf("\t\t\tSource: %v\n", formatIP(ipHead.Source))
		fmt.Printf("\t\t\tDestination: %v\n", formatIP(ipHead.Destination))
	}

	return ipHead
}

func ParseIPv6(rd io.Reader) ProtocolHeader {
	return IPv4Header{}
}
