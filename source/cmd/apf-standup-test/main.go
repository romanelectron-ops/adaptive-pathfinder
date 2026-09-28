// apf-standup-test — минимальный ручной инструмент для живой проверки роли «Выход» на
// Windows (Э-Выход-1/2, docs/PLAN_APF_VHOD_VYHOD_v1.0.md), тот же паттерн, что уже
// использовался живьём 2026-08-10 (см. память vhod-vyhod-tz-plan-status). НЕ часть
// продукта — не собирается в состав установщика, только ручной запуск с рабочей машины
// разработчика при явном разрешении на сетевые действия.
//
// Запускает sing-box.exe НАПРЯМУЮ (не через internal/singbox.Process/ServerRunner) —
// сознательно, ради диагностики: Process.OnLog нужно явно подключать, а ServerRunner
// интерфейс его не отдаёт наружу. Здесь важнее увидеть КАЖДУЮ строку [SERVER/...]
// (включая TRACE-уровень Reality-рукопожатия из vendored reality.go) вживую, чем
// использовать штатный жизненный цикл процесса.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

func main() {
	port := flag.Int("port", 28443, "порт, на котором слушает Reality-сервер")
	host := flag.String("host", "", "host для ссылки «Входу» (домен/IP, обязателен)")
	realityDest := flag.String("sni", "", "Reality SNI (пусто = singbox.GoodRealitySNI[0])")
	binDir := flag.String("bindir", `D:\APF-Stand\singbox-standup`, "каталог с sing-box.exe")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "нужен -host (адрес, по которому «Вход» достучится до этого звена)")
		os.Exit(1)
	}

	binPath := filepath.Join(*binDir, "sing-box.exe")
	if _, err := os.Stat(binPath); err != nil {
		fmt.Fprintln(os.Stderr, "sing-box.exe не найден:", binPath)
		os.Exit(1)
	}

	dataDir, err := os.MkdirTemp("", "apf-standup-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "MkdirTemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dataDir)

	identity, err := singbox.GenerateServerIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "GenerateServerIdentity:", err)
		os.Exit(1)
	}
	fmt.Println("identity UUID:", identity.UUID)

	dest := *realityDest
	if dest == "" {
		dest = singbox.GoodRealitySNI[0]
	}

	doc := singbox.BuildServerConfig(identity, *port, dest)
	// TRACE — иначе config.Log(...) в vendored reality.go (logger.Trace) не выводит
	// REALITY remoteAddr:/AuthKey/hs.c.conn строки, которые здесь и есть весь смысл.
	doc.Log.Level = "trace"
	data, err := singbox.ToServerJSON(doc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ToServerJSON:", err)
		os.Exit(1)
	}
	cfgPath := filepath.Join(dataDir, "current.json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "WriteFile:", err)
		os.Exit(1)
	}

	link := singbox.BuildServerLink(identity, *host, *port, dest, "APF-PC-standup")
	fmt.Println()
	fmt.Println("ССЫЛКА ДЛЯ «ВХОДА»:")
	fmt.Println(link)
	fmt.Println()
	fmt.Println("=== запускаю sing-box (вывод ниже, без фильтрации) ===")

	cmd := exec.Command(binPath, "run", "-c", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "Start:", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("останавливаю...")
		_ = cmd.Process.Kill()
	}()

	_ = cmd.Wait()
	fmt.Println("sing-box завершился")
}
