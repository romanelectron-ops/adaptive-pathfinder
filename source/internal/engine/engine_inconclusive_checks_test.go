package engine

import (
	"context"
	"testing"

	"github.com/apf/adaptive-pathfinder/internal/models"
)

// Регресс живого ПК 2026-10-27: фоновый скан пула шёл одновременно с применением Kill Switch и
// подъёмом TUN, и 27 из 70 узлов получили «blocked». Отказ локальной сети — не отказ узла.

// goodNode — узел, ранее проверенный и годный; адрес 127.0.0.1:0 не дозванивается мгновенно.
func goodNode() *models.Node {
	return &models.Node{
		ID: "n1", Address: "127.0.0.1", Port: 0, Protocol: "ss",
		Status: models.StatusOK, Score: 0.9, SuccessCount: 3,
	}
}

func TestCheckNodeSerialized_KSActive_FailureNotRecorded(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.ks = newProbeAllowerKS(true)
	n := goodNode()

	res := e.checkNodeSerialized(context.Background(), n)

	if res == nil || res.Success || res.Outcome != models.OutcomeFail {
		t.Fatalf("результат пробы должен вернуться как отказ вызывающему, got %+v", res)
	}
	if n.Status != models.StatusOK || n.FailCount != 0 || n.SuccessCount != 3 || n.Score != 0.9 {
		t.Errorf("отказ под активным Kill Switch записан в узел: status=%s fail=%d ok=%d score=%.2f",
			n.Status, n.FailCount, n.SuccessCount, n.Score)
	}
	if !n.BlacklistedUntil.IsZero() {
		t.Error("узел забанен из-за отказа под Kill Switch")
	}
}

func TestCheckNodeSerialized_NoKS_FailureRecorded(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	e.ks = newProbeAllowerKS(false)
	n := goodNode()

	e.checkNodeSerialized(context.Background(), n)

	if n.Status != models.StatusBlocked || n.FailCount != 1 {
		t.Errorf("без Kill Switch и туннеля отказ — настоящий и должен записываться: status=%s fail=%d",
			n.Status, n.FailCount)
	}
}

func TestCheckNodeSerialized_NonWindows_BehaviourUnchanged(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "android"
	e.ks = newProbeAllowerKS(true)
	n := goodNode()

	e.checkNodeSerialized(context.Background(), n)

	if n.Status != models.StatusBlocked || n.FailCount != 1 {
		t.Errorf("на не-Windows поведение прежнее (KS — на уровне ОС): status=%s fail=%d", n.Status, n.FailCount)
	}
}

// Сеть хоста изменилась ВО ВРЕМЯ проверки (Kill Switch применили посреди скана) — отказы
// недостоверны, даже если в начале проверка шла «чисто».
func TestGuardInconclusiveChecks_KSAppliedMidRun(t *testing.T) {
	e := newTestEngine()
	e.directProbeGOOS = "windows"
	ks := newProbeAllowerKS(false)
	e.ks = ks
	failed, alive := goodNode(), goodNode()
	failed.ID, alive.ID = "failed", "alive"

	results := e.guardInconclusiveChecks([]*models.Node{failed, alive}, func() []*models.CheckResult {
		// то, что делает checker: markFail у отказавшего и обновление у ответившего
		failed.Status, failed.FailCount, failed.Score = models.StatusBlocked, 1, 0
		alive.Status, alive.Score = models.StatusOK, 0.5
		ks.enabled = true // Kill Switch применён посреди скана
		return []*models.CheckResult{
			{Node: failed, Outcome: models.OutcomeFail},
			{Node: alive, Outcome: models.OutcomeOK, Success: true},
		}
	})

	if len(results) != 2 {
		t.Fatalf("результаты потеряны: %d", len(results))
	}
	if failed.Status != models.StatusOK || failed.FailCount != 0 || failed.Score != 0.9 {
		t.Errorf("отказ посреди смены сети записан: status=%s fail=%d score=%.2f", failed.Status, failed.FailCount, failed.Score)
	}
	if alive.Score != 0.5 {
		t.Errorf("успешная проба не должна откатываться, score=%.2f", alive.Score)
	}
}

func TestHostPath_Reliable(t *testing.T) {
	cases := []struct {
		h    hostPath
		want bool
	}{
		{hostPath{}, true},
		{hostPath{ks: true}, false},
		{hostPath{tunnel: true}, false},
		{hostPath{ks: true, tunnel: true}, false},
	}
	for _, c := range cases {
		if got := c.h.reliable(); got != c.want {
			t.Errorf("%+v.reliable() = %v, want %v", c.h, got, c.want)
		}
	}
}
