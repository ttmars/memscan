package pkg

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

type MemScanner struct {
	Bit         int        // 搜索位
	ProcessName string     // 进程名称
	PID         int        // 进程PID
	MemFD       *os.File   // 进程内存文件描述符
	PmapItems   []PmapItem // 可扫描内存段
	Result      []int64    // 当前搜索结果（偏移）
}

type PmapItem struct {
	Address string
	Kbytes  int
	RSS     int
	Dirty   int
	Mode    string
	Mapping string
}

func NewMemScanner(name string) (*MemScanner, error) {
	scan := &MemScanner{
		Bit:    32,
		Result: make([]int64, 0),
	}

	scan.ProcessName = name

	pid, err := GetPid(scan.ProcessName)
	if err != nil {
		return nil, err
	}
	scan.PID = pid

	f, err := os.OpenFile(fmt.Sprintf("/proc/%v/mem", scan.PID), os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	scan.MemFD = f

	scan.PmapItems, err = ParsePmap(scan.PID)
	if err != nil {
		return nil, err
	}

	return scan, nil
}

func (m *MemScanner) Close() {
	if m.MemFD != nil {
		m.MemFD.Close()
	}
}

// 清除扫描结果
func (m *MemScanner) Clear() {
	if m.Result != nil {
		m.Result = m.Result[:0]
	}
}

// 打印匹配结果
func (m *MemScanner) PrintResult() {
	fmt.Printf("匹配数量：%v\n", len(m.Result))
	flag := false
	num := len(m.Result)
	if num >= 10 {
		num = 10
		flag = true
	}
	for i := 0; i < num; i++ {
		fmt.Printf("0x%x\n", m.Result[i])
	}
	if flag {
		fmt.Println("...")
	}
}

// 打印pmap
func (m *MemScanner) PrintPmap() {
	fmt.Printf("%-20v %-8v %-8v %-8v %-10v %-10v\n", "Address", "Kbytes", "RSS", "Dirty", "Mode", "Mapping")
	for _, item := range m.PmapItems {
		fmt.Printf("%-20v %-8v %-8v %-8v %-10v %-10v\n", item.Address, item.Kbytes, item.RSS, item.Dirty, item.Mode, item.Mapping)
	}
}

// 设置搜索类型
func (m *MemScanner) SetBit(b string) {
	bit, err := strconv.ParseInt(b, 10, 8)
	if err != nil {
		return
	}
	if bit == 8 || bit == 16 || bit == 32 || bit == 64 {
		m.Bit = int(bit)
	}
}

// 打印内存段，start起始地址，off偏移，单位：byte
func (m *MemScanner) PrintMem(startStr string, offStr string) {
	startStr = strings.TrimPrefix(startStr, "0x")
	start, err := strconv.ParseInt(startStr, 16, 64)
	if err != nil {
		fmt.Println(err)
		return
	}
	off, err := strconv.ParseInt(offStr, 10, 64)
	if err != nil {
		fmt.Println(err)
		return
	}

	m.MemFD.Seek(start, 0)
	b := make([]byte, off)
	n, err := m.MemFD.Read(b)
	if err != nil {
		fmt.Println("读取失败！")
		return
	}
	fmt.Printf("read:%-11v\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02X %02X %02X %02X %02X %02X\n", n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	for i := 0; i < n; i++ {
		if i != 0 && i%16 == 0 {
			fmt.Println()
		}
		if i%16 == 0 {
			fmt.Printf("0x%016x\t", start+int64(i))
		}
		fmt.Printf("%02x ", b[i])
	}
	fmt.Println()
}

// 写入值
func (m *MemScanner) Overwrite(value string) {
	int8Value, int8ValueErr := strconv.ParseInt(value, 10, 8)
	buf8 := new(bytes.Buffer)
	buf8Err := binary.Write(buf8, binary.LittleEndian, int8(int8Value))

	int16Value, int16ValueErr := strconv.ParseInt(value, 10, 16)
	buf16 := new(bytes.Buffer)
	buf16Err := binary.Write(buf16, binary.LittleEndian, int16(int16Value))

	int32Value, int32ValueErr := strconv.ParseInt(value, 10, 32)
	buf32 := new(bytes.Buffer)
	buf32Err := binary.Write(buf32, binary.LittleEndian, int32(int32Value))

	int64Value, int64ValueErr := strconv.ParseInt(value, 10, 64)
	buf64 := new(bytes.Buffer)
	buf64Err := binary.Write(buf64, binary.LittleEndian, int64(int64Value))

	// 默认写入int8,int16,int32,int64
	for _, v := range m.Result {
		switch m.Bit {
		case 8:
			if int8ValueErr == nil && buf8Err == nil {
				m.MemFD.Seek(v, 0)
				n, err := m.MemFD.Write(buf8.Bytes())
				if err != nil {
					fmt.Println("写入失败")
				} else {
					fmt.Println("写入成功", n, buf8.Bytes())
				}
			} else {
				fmt.Println("写入失败!")
			}
		case 16:
			if int16ValueErr == nil && buf16Err == nil {
				m.MemFD.Seek(v, 0)
				n, err := m.MemFD.Write(buf16.Bytes())
				if err != nil {
					fmt.Println("写入失败")
				} else {
					fmt.Println("写入成功", n, buf16.Bytes())
				}
			} else {
				fmt.Println("写入失败!")
			}
		case 32:
			if int32ValueErr == nil && buf32Err == nil {
				m.MemFD.Seek(v, 0)
				n, err := m.MemFD.Write(buf32.Bytes())
				if err != nil {
					fmt.Println("写入失败")
				} else {
					fmt.Println("写入成功", n, buf32.Bytes())
				}
			} else {
				fmt.Println("写入失败!")
			}
		case 64:
			if int64ValueErr == nil && buf64Err == nil {
				m.MemFD.Seek(v, 0)
				n, err := m.MemFD.Write(buf64.Bytes())
				if err != nil {
					fmt.Println("写入失败")
				} else {
					fmt.Println("写入成功", n, buf64.Bytes())
				}
			} else {
				fmt.Println("写入失败!")
			}
		}
	}
}

// 扫描内存段
func (m *MemScanner) Scan(value string) {
	int8Value, int8ValueErr := strconv.ParseInt(value, 10, 8)
	int16Value, int16ValueErr := strconv.ParseInt(value, 10, 16)
	int32Value, int32ValueErr := strconv.ParseInt(value, 10, 32)
	int64Value, int64ValueErr := strconv.ParseInt(value, 10, 64)

	uint8Value, uint8ValueErr := strconv.ParseUint(value, 10, 8)
	uint16Value, uint16ValueErr := strconv.ParseUint(value, 10, 16)
	uint32Value, uint32ValueErr := strconv.ParseUint(value, 10, 32)
	uint64Value, uint64ValueErr := strconv.ParseUint(value, 10, 64)

	float32Value, float32ValueErr := strconv.ParseFloat(value, 32)
	float64Value, float64ValueErr := strconv.ParseFloat(value, 64)

	// 扫描结果集
	if len(m.Result) > 0 {
		var sli []int64
		b1 := make([]byte, 1)
		b2 := make([]byte, 2)
		b3 := make([]byte, 4)
		b4 := make([]byte, 8)
		for _, v := range m.Result {
			switch m.Bit {
			case 8:
				m.MemFD.Seek(v, 0)
				m.MemFD.Read(b1)
				int8V := *(*int8)(unsafe.Pointer(&b1[0]))
				if int8ValueErr == nil && int8V == int8(int8Value) {
					sli = append(sli, v)
				}
			case 16:
				m.MemFD.Seek(v, 0)
				m.MemFD.Read(b2)
				int16V := *(*int16)(unsafe.Pointer(&b2[0]))
				if int16ValueErr == nil && int16V == int16(int16Value) {
					sli = append(sli, v)
				}
			case 32:
				m.MemFD.Seek(v, 0)
				m.MemFD.Read(b3)
				int32V := *(*int32)(unsafe.Pointer(&b3[0]))
				if int32ValueErr == nil && int32V == int32(int32Value) {
					sli = append(sli, v)
				}
			case 64:
				m.MemFD.Seek(v, 0)
				m.MemFD.Read(b4)
				int64V := *(*int64)(unsafe.Pointer(&b4[0]))
				if int64ValueErr == nil && int64V == int64(int64Value) {
					sli = append(sli, v)
				}
			}
		}
		m.Result = sli
		return
	}

	// 扫描所有内存段
	for _, item := range m.PmapItems {
		mem := make([]byte, item.Kbytes*1024)
		start, err := strconv.ParseInt(item.Address, 16, 64)
		if err != nil {
			log.Fatal(err)
		}
		m.MemFD.Seek(start, 0)
		_, err = m.MemFD.Read(mem)
		// fmt.Println(n, err)

		// 扫描内存
		for i := 0; i < len(mem); i++ {
			if m.Bit == 8 {
				int8V := *(*int8)(unsafe.Pointer(&mem[i]))
				uint8V := *(*uint8)(unsafe.Pointer(&mem[i]))
				if (int8ValueErr == nil && int8V == int8(int8Value)) || (uint8ValueErr == nil && uint8V == uint8(uint8Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 16 {
				int16V := *(*int16)(unsafe.Pointer(&mem[i]))
				uint16V := *(*uint16)(unsafe.Pointer(&mem[i]))
				if (int16ValueErr == nil && int16V == int16(int16Value)) || (uint16ValueErr == nil && uint16V == uint16(uint16Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 32 {
				int32V := *(*int32)(unsafe.Pointer(&mem[i]))
				uint32V := *(*uint32)(unsafe.Pointer(&mem[i]))
				float32V := *(*float32)(unsafe.Pointer(&mem[i]))
				if (int32ValueErr == nil && int32V == int32(int32Value)) || (uint32ValueErr == nil && uint32V == uint32(uint32Value)) || (float32ValueErr == nil && float32V == float32(float32Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 64 {
				int64V := *(*int64)(unsafe.Pointer(&mem[i]))
				uint64V := *(*uint64)(unsafe.Pointer(&mem[i]))
				float64V := *(*float64)(unsafe.Pointer(&mem[i]))
				if (int64ValueErr == nil && int64V == int64Value) || (uint64ValueErr == nil && uint64V == uint64Value) || (float64ValueErr == nil && float64V == float64Value) {
					m.Result = append(m.Result, start+int64(i))
				}
			}
		}
	}

	return
}

// 获取可读可写的内存段，并排除动态链接库
func ParsePmap(pid int) ([]PmapItem, error) {
	var result []PmapItem
	cmd := exec.Command("pmap", "-xq", strconv.Itoa(pid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	scan := bufio.NewScanner(bytes.NewReader(out))
	for scan.Scan() {
		sli := strings.Fields(scan.Text())
		if len(sli) == 6 && len(sli[4]) >= 2 && sli[4][:2] == "rw" && !strings.HasSuffix(sli[5], "so") {
			Kbytes, _ := strconv.Atoi(sli[1])
			RSS, _ := strconv.Atoi(sli[2])
			Dirty, _ := strconv.Atoi(sli[3])
			result = append(result, PmapItem{Address: sli[0], Kbytes: Kbytes, RSS: RSS, Dirty: Dirty, Mode: sli[4], Mapping: sli[5]})
		}
		if len(sli) == 8 && len(sli[4]) >= 2 && sli[4][:2] == "rw" && !strings.HasSuffix(sli[6], "so") {
			Kbytes, _ := strconv.Atoi(sli[1])
			RSS, _ := strconv.Atoi(sli[2])
			Dirty, _ := strconv.Atoi(sli[3])
			result = append(result, PmapItem{Address: sli[0], Kbytes: Kbytes, RSS: RSS, Dirty: Dirty, Mode: sli[4], Mapping: sli[6]})
		}
	}
	return result, nil
}

// 获取进程的PID
func GetPid(process string) (int, error) {
	cmd := exec.Command("pidof", process)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return -1, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1, err
	}
	return pid, nil
}
