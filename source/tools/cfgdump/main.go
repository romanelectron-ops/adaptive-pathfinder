// Харнесс генерации эталонных sing-box конфигов для валидации через `sing-box check`.
// Запуск: go run ./tools/cfgdump <outDir>
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

func write(dir, name string, cfg *singbox.Config, err error) {
	if err != nil {
		fmt.Printf("FAIL build %s: %v\n", name, err)
		return
	}
	b, e := singbox.ToJSON(cfg)
	if e != nil {
		fmt.Printf("FAIL json %s: %v\n", name, e)
		return
	}
	if e := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); e != nil {
		fmt.Printf("FAIL write %s: %v\n", name, e)
		return
	}
	fmt.Printf("OK %s.json\n", name)
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	_ = os.MkdirAll(dir, 0o755)

	vless := &models.Node{
		ID: "n-vless", Name: "vless", Protocol: models.ProtoVLESS,
		Address: "203.0.113.10", Port: 443, UUID: "11111111-2222-3333-4444-555555555555",
		Flow: "xtls-rprx-vision",
		TLS:  &models.TLSConfig{Enabled: true, ServerName: "www.microsoft.com", Reality: &models.RealityConfig{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123abcd"}},
	}
	vmess := &models.Node{
		ID: "n-vmess", Name: "vmess", Protocol: models.ProtoVMess,
		Address: "203.0.113.11", Port: 443, UUID: "11111111-2222-3333-4444-555555555555",
		TLS:       &models.TLSConfig{Enabled: true, ServerName: "example.com"},
		Transport: &models.TransportConfig{Type: "ws", Path: "/vm", Host: "example.com"},
	}
	trojan := &models.Node{
		ID: "n-trojan", Name: "trojan", Protocol: models.ProtoTrojan,
		Address: "203.0.113.12", Port: 443, Password: "trojanpass",
		TLS: &models.TLSConfig{Enabled: true, ServerName: "example.com"},
	}
	ss := &models.Node{
		ID: "n-ss", Name: "ss", Protocol: models.ProtoShadowsocks,
		Address: "203.0.113.13", Port: 8388, Method: "aes-256-gcm", Password: "sspass",
	}

	b := singbox.NewBuilder(10808, false)
	c, e := b.BuildSingle(vless)
	write(dir, "vless", c, e)
	c, e = b.BuildSingle(vmess)
	write(dir, "vmess", c, e)
	c, e = b.BuildSingle(trojan)
	write(dir, "trojan", c, e)
	c, e = b.BuildSingle(ss)
	write(dir, "shadowsocks", c, e)

	tun := singbox.NewBuilder(10808, true)
	c, e = tun.BuildSingle(vless)
	write(dir, "vless_tun", c, e)

	bs := singbox.NewBuilder(10808, false)
	bs.SetShadowTLS(&singbox.ShadowTLSParams{Server: "203.0.113.20", Port: 443, Version: 3, Password: "stlspw", SNI: "www.apple.com"})
	c, e = bs.BuildSingle(vless)
	write(dir, "vless_shadowtls", c, e)

	bc := singbox.NewBuilder(10808, false)
	bc.SetCDNFronting(&singbox.CDNParams{Server: "104.16.0.1", Port: 443, SNI: "cdn.example.com", WSPath: "/ws", WSHost: "worker.example.com"})
	c, e = bc.BuildSingle(vmess)
	write(dir, "vmess_cdn", c, e)

	c, e = b.BuildChain(&models.Chain{Nodes: []*models.Node{vless, trojan}})
	write(dir, "chain", c, e)

	write(dir, "tor", b.BuildTor(), nil)

	fmt.Println("DONE")
}
