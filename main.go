package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	path := fmt.Sprintf("/proc/%v/mem", os.Args[1])
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	ff, err := os.OpenFile("demo_mem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer ff.Close()

	f.Seek(0x7f0cfc4ef000, 0)
	b := make([]byte, 1024*4)
	n, err := f.Read(b)
	fmt.Println(n, err)

	nn, err := ff.Write(b[:n])
	fmt.Println(nn, err)
}
