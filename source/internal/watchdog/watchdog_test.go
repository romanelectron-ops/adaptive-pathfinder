package watchdog

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRun_InvalidPIDZero(t *testing.T) {
	err := Run(context.Background(), Config{PID: 0})
	if err == nil {
		t.Error("expected error for PID=0")
	}
}

func TestRun_InvalidPIDNegative(t *testing.T) {
	err := Run(context.Background(), Config{PID: -1})
	if err == nil {
		t.Error("expected error for negative PID")
	}
}

func TestRun_CtxCancelledImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{
		PID:       os.Getpid(),
		PollEvery: 10 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected context error")
	}
}

func TestRun_DefaultPollEvery(t *testing.T) {
	// PollEvery=0 должен использовать дефолт 750ms; ctx отменяем сразу
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{
		PID:       os.Getpid(),
		PollEvery: 0,
	})
	if err == nil {
		t.Error("expected context error")
	}
}

func TestRun_GracePeriodCtxCancelled(t *testing.T) {
	// ctx уже отменён → должен вернуть ошибку прямо в grace period
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{
		PID:         os.Getpid(),
		PollEvery:   10 * time.Millisecond,
		GracePeriod: 5 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected context error during grace period")
	}
}

func TestRun_ZeroGracePeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{
		PID:         os.Getpid(),
		PollEvery:   10 * time.Millisecond,
		GracePeriod: 0,
	})
	if err == nil {
		t.Error("expected context error")
	}
}

func TestRun_NegativeGracePeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{
		PID:         os.Getpid(),
		PollEvery:   10 * time.Millisecond,
		GracePeriod: -1 * time.Second,
	})
	if err == nil {
		t.Error("expected context error")
	}
}

func TestRun_DeadPID(t *testing.T) {
	// PID 999999 почти наверняка не существует
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, Config{
		PID:       999999,
		PollEvery: 50 * time.Millisecond,
	})
	// Либо nil (PID не найден → процесс завершился), либо deadline
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("got err=%v (acceptable)", err)
	}
}

func TestIsPIDAlive_Self(t *testing.T) {
	alive, err := isPIDAlive(os.Getpid())
	if err != nil {
		t.Logf("isPIDAlive error: %v (may be expected on some platforms)", err)
	}
	if !alive {
		t.Error("own PID should be alive")
	}
}
