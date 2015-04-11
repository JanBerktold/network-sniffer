package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

var file *os.File

type EthernetHeader struct {
}

func init() {
	name := flag.String("file", "output", "File to parse")
	flag.Parse()

	if lFile, err := os.Open(*name); err == nil {
		file = lFile
	} else {
		fmt.Printf("Failed to open file with error %q\n", err.Error())
		os.Exit(-1)
	}
}

func main() {
	reader := bufio.NewReader(file)

	dstMacAddr := make([]byte, 6)
	srcMacAddr := make([]byte, 6)

	var packLen int32

	for {
		binary.Read(reader, binary.LittleEndian, &packLen)

		fmt.Printf("\tGot new package with length %v\n", packLen)
		fmt.Printf("\t( Layer 2 :: Ethernet Header )\n")

		reader.ReadByte()
		reader.ReadByte()

		reader.Read(dstMacAddr)
		reader.Read(srcMacAddr)

		fmt.Printf("\t\tDestination Mac Address: %v\n", dstMacAddr)
		fmt.Printf("\t\tSource Mac Address: %v\n", srcMacAddr)

		return
	}
}
