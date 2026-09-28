package singbox

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Контракт «версия бинарника ↔ схема конфигурации» (дефект D-A27).
//
// Вход:      SingBoxVersion (что мы скачиваем и кладём в APK) и MinSingBoxVersion
//
//	(что требует сборщик конфигурации).
//
// Тело:      сравнение версий по правилам semver.
// Выход:     отказ, если бинарник старее схемы.
// Инвариант: не существует сборки, где sing-box не понимает конфигурацию, которую APF ему
//
//	выдаёт.
//
// Почему это отдельный тест, а не проверка «на живом бинарнике». Прогон тестов не имеет
// права ходить в сеть (см. internal/netguard), а бинарника sing-box рядом с тестовым
// процессом обычно нет — проверка «запусти и посмотри» на практике всегда пропускалась бы.
// Здесь же сторож срабатывает всегда и стоит нисколько.
//
// Цена ошибки, которую он ловит: расхождение не проявляется ни при сборке, ни в тестах,
// ни при запуске приложения — только в момент подключения, и выглядит как сетевая
// неисправность. На телефоне оно стоило полного цикла «собрать → поставить → нажать».
func TestSingBoxVersion_SatisfiesConfigSchema(t *testing.T) {
	got, err := parseVersion(SingBoxVersion)
	if err != nil {
		t.Fatalf("SingBoxVersion = %q: %v", SingBoxVersion, err)
	}
	need, err := parseVersion(MinSingBoxVersion)
	if err != nil {
		t.Fatalf("MinSingBoxVersion = %q: %v", MinSingBoxVersion, err)
	}

	if compareVersions(got, need) < 0 {
		t.Fatalf(
			"sing-box %s старее схемы конфигурации (нужна >= %s).\n"+
				"Такой бинарник откажется разбирать конфигурацию целиком:\n"+
				"  FATAL decode config: dns.servers[0].type: json: unknown field \"type\"\n"+
				"Либо поднимите SingBoxVersion в process.go (и перевыложите нативную\n"+
				"библиотеку: tools\\android\\fetch_singbox.ps1 -Apply), либо верните схему\n"+
				"в config_builder.go к старому формату и понизьте MinSingBoxVersion.",
			SingBoxVersion, MinSingBoxVersion)
	}
}

// Сама схема тоже проверяется: если поле "type" из DNS-сервера исчезнет, требование
// версии 1.12+ станет ложным, а тест выше — бессмысленным ритуалом.
func TestConfigSchema_StillUsesNewDNSFormat(t *testing.T) {
	cfg := NewBuilder(1080, false).BuildTor()
	if len(cfg.DNS.Servers) == 0 {
		t.Skip("сборщик не выдал DNS-серверов — проверять нечего")
	}
	if cfg.DNS.Servers[0].Type == "" {
		t.Error("DNS-сервер без поля \"type\": схема вернулась к формату до 1.12 — " +
			"тогда MinSingBoxVersion обязана быть понижена, иначе требование ложное")
	}
}

// parseVersion разбирает «1.13.16» в [3]int. Суффиксы вида «-beta.7» отбрасываются:
// для сравнения «не старее» они значения не имеют.
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, fmt.Errorf("не похоже на версию")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("часть %q не число", p)
		}
		out[i] = n
	}
	return out, nil
}

func compareVersions(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
