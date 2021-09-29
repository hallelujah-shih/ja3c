package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dreadl0ck/tlsx"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"
)

type PerfMetadata struct {
	Cookie uint16
	Len    uint16
}

func (pm *PerfMetadata) UnmarshalBinary(data []byte) error {
	if len(data) != 4 {
		return fmt.Errorf("invalid metadata")
	}
	pm.Cookie = binary.LittleEndian.Uint16(data[:2])
	pm.Len = binary.LittleEndian.Uint16(data[2:])
	return nil
}

type Counter struct {
	Total uint64
}

var (
	globalCfg Config
)

type Config struct {
	PinBasePath string `json:"pin_base_path"`
	DevName     string `json:"dev_name"`
	EbpfFile    string `json:"ebpf_file"`
}

func basicConfig(configPath string) error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	globalCfg = cfg
	return nil
}

func UnlimitLockedMemory() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

func DigestHexPacket(p gopacket.Packet) string {

	bare := BarePacket(p)
	if len(bare) == 0 {
		return ""
	}

	sum := md5.Sum(bare)
	ja3hash := hex.EncodeToString(sum[:])
	fmt.Println("ja3-client hash:", ja3hash, "string:", string(bare))
	return ja3hash
}

// BarePacket returns the Ja3 digest if the supplied packet contains a TLS client hello
// otherwise returns an empty string
func BarePacket(p gopacket.Packet) []byte {
	if tl := p.TransportLayer(); tl != nil {
		if tcp, ok := tl.(*layers.TCP); ok {
			if tcp.SYN {
				// Connection setup
			} else if tcp.FIN {
				// Connection teardown
			} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
				// Acknowledgement packet
			} else if tcp.RST {
				// Unexpected packet
			} else {
				// data packet
				var (
					hello = tlsx.ClientHelloBasic{}
					err   = hello.Unmarshal(tcp.LayerPayload())
				)
				if err != nil {
					fmt.Println(err)
					return []byte{}
				}

				// return JA3 bare
				return Bare(&hello)
			}
		}
	}
	return []byte{}
}

func capture(name string, bpfMap *ebpf.Map) {
	pageSize := os.Getpagesize()
	reader, err := perf.NewReader(bpfMap, pageSize*8)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer reader.Close()
	var rawPktBuf [65536]byte
	for {
		record, err := reader.Read()
		switch {
		case perf.IsClosed(err):
			fmt.Println("closed reader")
			return
		case err != nil:
			fmt.Println("read error:", err)
			continue
		}

		if record.LostSamples > 0 {
			fmt.Println("perf-event: lost pkgs:", record.LostSamples)
		}

		data := record.RawSample
		dataLen := uint32(len(data))
		if dataLen < 4 {
			continue
		}

		var meta PerfMetadata
		if err := meta.UnmarshalBinary(data[:4]); err != nil {
			panic("metadata unmarshal error")
		}

		if meta.Cookie == 0xcafe && meta.Len+4 <= uint16(dataLen) {
			copy(rawPktBuf[:], data[4:])
			samplePacket := gopacket.NewPacket(rawPktBuf[:meta.Len], layers.LayerTypeEthernet, gopacket.Default)
			DigestHexPacket(samplePacket)
		}
	}
}

func attach() {
	os.MkdirAll(globalCfg.PinBasePath, 0777)
	collSpec, err := ebpf.LoadCollectionSpec(globalCfg.EbpfFile)
	if err != nil {
		fmt.Println("coll spec error:", err)
		return
	}

	for _, ms := range collSpec.Maps {
		if ms.Type == ebpf.PerfEventArray {
			ms.MaxEntries = PossibleCPUs()
		}
	}

	bpfColl, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  ebpf.DefaultVerifierLogSize,
		},
	})
	if err != nil {
		fmt.Println("create collection error:", err)
		return
	}

	root := bpfColl.Programs["root"]
	if root == nil {
		fmt.Println("ebpf prog not found!")
		return
	}
	var capName string
	var capMap *ebpf.Map
	for mn, mm := range bpfColl.Maps {
		p := filepath.Join(globalCfg.PinBasePath, mn)
		if err := mm.Pin(p); err != nil {
			fmt.Println("error:", err)
			return
		}
		if mm.Type() == ebpf.PerfEventArray {
			capName = mn
			capMap = mm
		}
	}

	link, err := netlink.LinkByName(globalCfg.DevName)
	if err != nil {
		fmt.Println("netlink error:", err)
		return
	}

	if err := netlink.LinkSetXdpFd(link, root.FD()); err != nil {
		fmt.Println("set xdp error:", err)
		return
	}
	fmt.Println("load success!")

	capture(capName, capMap)
}

func detach() {
	link, err := netlink.LinkByName(globalCfg.DevName)
	if err != nil {
		fmt.Println("netlink error:", err)
		return
	}
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		fmt.Println("netlink set -1 error:", err)
		return
	}
	os.RemoveAll(globalCfg.PinBasePath)
}

func main() {
	app := &cli.App{
		Name:        "xdp sample test",
		HelpName:    "xdp sample test",
		Description: "xdp sample test",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c"},
				Usage:    "input config filename",
				Required: true,
			},
		},
		Commands: []*cli.Command{
			{
				Name: "attach",
				Action: func(context *cli.Context) error {
					cfgName := context.String("config")
					if err := basicConfig(cfgName); err != nil {
						return err
					}

					UnlimitLockedMemory()
					cmd := exec.Command("sh", "-c", "/bin/mountpoint -q /sys/fs/bpf || /bin/mount bpffs /sys/fs/bpf -t bpf")
					if _, err := cmd.CombinedOutput(); err != nil {
						return fmt.Errorf("excute mount bpffs error: %v", err)
					}
					attach()
					return nil
				},
			},
			{
				Name: "detach",
				Action: func(context *cli.Context) error {
					cfgName := context.String("config")
					if err := basicConfig(cfgName); err != nil {
						return err
					}

					detach()
					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
