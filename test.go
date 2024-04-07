package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Stu struct {
	b byte
	a int
	d string
	c byte
}

func main() {
	// var c Stu
	// fmt.Println(unsafe.Sizeof(c))

	// 要转换为小端字节序的整数
	var myInt int32 = 12345

	// 缓冲区用于存储字节
	buf := new(bytes.Buffer)

	// 将整数写入缓冲区（小端格式）
	err := binary.Write(buf, binary.LittleEndian, myInt)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}

	// 输出字节序列
	fmt.Printf("% x\n", buf.Bytes())
}
