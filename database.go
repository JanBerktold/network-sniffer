package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

var (
	file    *os.File
	name    string
	verbose bool
)

type EthernetHeader struct {
	Destination, Source []byte
	Type                uint16
	//FCS                 int32
}

type IPHeader struct {
	Version        byte
	HeaderLength   byte
	TypeOfService  int16
	TotalLength    uint16
	Identification uint16
	Flags          byte // 3
	FragmentOffset byte // 13
	TimeToLive     int8
	Protocol       int8
	HeaderChecksum int16
	Source         int32
	Destination    int32
}

func init() {
	flag.StringVar(&name, "file", "output", "File to parse")
	flag.BoolVar(&verbose, "v", true, "whether to print while uploading")
	flag.Parse()

	if lFile, err := os.Open(name); err == nil {
		file = lFile
	} else {
		fmt.Printf("Failed to open file with error %q\n", err.Error())
		os.Exit(-1)
	}
}

func formatMac(b []byte) string {
	return fmt.Sprintf(
		"%x::%x::%x::%x::%x::%x",
		b[0], b[1], b[2], b[3], b[4], b[5],
	)
}

func main() {
	reader := bufio.NewReader(file)

	ethHead := EthernetHeader{
		Destination: make([]byte, 6),
		Source:      make([]byte, 6),
	}

	ipHead := IPHeader{}

	var packLen uint32
	var count int

	m := map[string]bool{}
	for {
		count++

		if err := binary.Read(reader, binary.LittleEndian, &packLen); err != nil {
			fmt.Println("Reached end")
			break
		}

		if verbose {
			fmt.Printf("\t-- Total Length: %v --\n", packLen)
		}

		reader.Read(ethHead.Destination)
		reader.Read(ethHead.Source)
		binary.Read(reader, binary.BigEndian, &ethHead.Type)

		m[formatMac(ethHead.Destination)] = true
		m[formatMac(ethHead.Source)] = true
		if verbose {
			fmt.Printf("\t-- Layer 2 :: Ethernet Header --\n")
			fmt.Printf("\t\tDestination: %v\n", formatMac(ethHead.Destination))
			fmt.Printf("\t\tSource: %v\n", formatMac(ethHead.Source))
			fmt.Printf("\t\tType: %#X\n", ethHead.Type)
		}

		firstByte, _ := reader.ReadByte()

		ipHead.Version = firstByte >> 4
		ipHead.HeaderLength = firstByte & 0x0F

		binary.Read(reader, binary.BigEndian, &ipHead.TypeOfService)
		binary.Read(reader, binary.BigEndian, &ipHead.TotalLength)
		binary.Read(reader, binary.BigEndian, &ipHead.Identification)

//		fragmentByte, _ := reader.ReadByte()

		if verbose {
			fmt.Printf("\t\t-- Layer 3 :: IP Header --\n")
			fmt.Printf("\t\t\tVersion: %v\n", ipHead.Version)
			fmt.Printf("\t\t\tHeader Length: %v\n", ipHead.HeaderLength)
			fmt.Printf("\t\t\tType of Service: %v\n", ipHead.TypeOfService)
			fmt.Printf("\t\t\tTotal Length: %v\n", ipHead.TotalLength)
			fmt.Printf("\t\t\tIdentification: %v\n", ipHead.Identification)

		}

		otherData := make([]byte, packLen-14-1-6)
		reader.Read(otherData)

//		if count == 4 {
//			break
//		}
	}
	fmt.Printf("Handled %v packages\n", count)
	fmt.Printf("%v unique MAC adresses\n", len(m))
}
