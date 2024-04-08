package main

import (
	"bufio"
	"fmt"
	"memscan/pkg"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("参数错误！")
		return
	}

	scan, err := pkg.NewMemScanner(os.Args[1])
	if err != nil {
		fmt.Println("进程载入失败！", err)
		return
	}
	defer scan.Close()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("(%v %v %v) ", scan.ProcessName, scan.PID, scan.Bit)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("输入错误！", err)
			continue
		}
		sli := strings.Fields(input)

		if len(sli) == 1 && (sli[0] == "help" || sli[0] == "h") {
			PrintHelp()
			continue
		}

		if len(sli) == 1 && (sli[0] == "quit" || sli[0] == "q") {
			fmt.Println("bye")
			return
		}

		if len(sli) == 1 && (sli[0] == "clear" || sli[0] == "c") {
			scan.Clear()
			fmt.Println("success")
			continue
		}

		if len(sli) == 1 && (sli[0] == "print" || sli[0] == "p") {
			scan.PrintResult()
			continue
		}

		if len(sli) == 1 && sli[0] == "pmap" {
			scan.PrintPmap()
			continue
		}

		if len(sli) == 2 && (sli[0] == "set" || sli[0] == "s") {
			bit, _ := strconv.ParseInt(sli[1], 10, 8)
			scan.SetBit(int(bit))
			continue
		}

		if len(sli) == 2 && (sli[0] == "find" || sli[0] == "f") {
			scan.Scan(sli[1])
			scan.PrintResult()
			continue
		}

		if len(sli) == 2 && (sli[0] == "write" || sli[0] == "w") {
			scan.Overwrite(sli[1])
			continue
		}

		PrintHelp()
	}
}

func PrintHelp() {
	fmt.Printf(`help,h			帮助
quit,q			退出
clear,c			清除搜索结果
print,p			打印搜索结果
pmap			打印进程地址空间
set,s	<bit>		设置搜索类型(8,16,32,64),默认32
find,f	<value>		搜索
write,w	<value> 	写入

`)
}
