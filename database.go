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

	dstMacAddr := make([]byte, 6)
	srcMacAddr := make([]byte, 6)

	var packLen int32
	var count int

	for {
		count++

		if err := binary.Read(reader, binary.LittleEndian, &packLen); err != nil {
			fmt.Println("Reached end")
			break
		}

		if verbose {
			fmt.Printf("\tGot new package with length %v\n", packLen)
			fmt.Printf("\t( Layer 2 :: Ethernet Header )\n")
		}

		reader.Read(dstMacAddr)
		reader.Read(srcMacAddr)

		if verbose {
			fmt.Printf("\t\tDestination Mac Address: %v\n", formatMac(dstMacAddr))
			fmt.Printf("\t\tSource Mac Address: %v\n", formatMac(srcMacAddr))
			fmt.Printf("\t\t( Layer 3 :: IP Header )\n")
		}

		if verbose {
			fmt.Printf("\t\t\t( Layer 4 :: TCP Header )\n")
		}

		otherData := make([]byte, packLen+2-12)
		reader.Read(otherData)

		if count == 50 {
			break
		}
	}
	fmt.Printf("Handled %v packages\n", count)
}
