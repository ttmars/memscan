package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
)

func main() {

}

// 数值与字节序互转
func convert() {
	var a int64 = 8888
	fmt.Println(a)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, a)
	if err != nil {
		log.Fatal(err)
	}
	b := buf.Bytes()
	fmt.Println(b, len(b), cap(b))

	v := binary.LittleEndian.Uint64(b)
	fmt.Println(v)
}
