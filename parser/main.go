package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

var (
	file                 *os.File
	name                 string
	dataConnectionString string
	verbose              bool
)

func init() {
	flag.StringVar(&name, "file", "output", "File to parse")
	flag.StringVar(&dataConnectionString, "db", "", "String to connect to the target SQL database")
	flag.BoolVar(&verbose, "v", true, "whether to print while uploading")
	flag.Parse()

	if lFile, err := os.Open(name); err == nil {
		file = lFile
	} else {
		fmt.Printf("Failed to open file with error %q\n", err.Error())
		os.Exit(-1)
	}

	if len(dataConnectionString) > 0 {
		initConnection()
	}
}

func formatMac(b []byte) string {
	return fmt.Sprintf(
		"%x::%x::%x::%x::%x::%x",
		b[0], b[1], b[2], b[3], b[4], b[5],
	)
}

func formatIP(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(a>>24), byte(a>>16), byte(a>>8), byte(a))
}

// TODO(Jan Berktold): Implement FragmentOffset
func main() {
	gReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Printf("Failed error while opening file: %q\n", err.Error())
	}
	reader := bufio.NewReader(gReader)

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

		fragmentByte1, _ := reader.ReadByte()
		reader.ReadByte() // second byte used for FragmentOffset

		notFragment := fragmentByte1 >> 5
		moreFragment := fragmentByte1 >> 6

		ipHead.ForbidFragment = notFragment == 1
		ipHead.MoreFragments = moreFragment == 1

		binary.Read(reader, binary.BigEndian, &ipHead.TimeToLive)
		binary.Read(reader, binary.BigEndian, &ipHead.Protocol)
		binary.Read(reader, binary.BigEndian, &ipHead.HeaderChecksum)
		binary.Read(reader, binary.BigEndian, &ipHead.Source)
		binary.Read(reader, binary.BigEndian, &ipHead.Destination)

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

		otherData := make([]byte, packLen-14-1-6-2-2-2-4-3)
		reader.Read(otherData)

		if count == 50 {
			break
		}
	}
	fmt.Printf("Handled %v packages\n", count)
	fmt.Printf("%v unique MAC adresses\n", len(m))
	for ip, _ := range m {
		fmt.Printf("%v\n", ip)
	}
}
