package main

// S-8 (ТЗ v1.4, лот L1b-CLI): web.Server.Close() (K2-W) не вызывался владельцем процесса —
// apfService.Execute (svc.Stop/svc.Shutdown) звал только eng.Stop(). Тест — на инжектируемый
// шов stopProcess(webCloser, engineStopper) напрямую: реальную службу Windows/сеть в этом
// лоте поднимать нельзя (правило "не запускать бинарники"), а svc.Handler.Execute требует
// живого SCM-канала req/resp, который недоступен вне настоящей службы.

import "testing"

type fakeWebCloser struct{ closed bool }

func (f *fakeWebCloser) Close() { f.closed = true }

type fakeEngineStopper struct{ stopped bool }

func (f *fakeEngineStopper) Stop() { f.stopped = true }

// TestS8_StopProcess_ClosesWebThenStopsEngine — путь остановки владельца (svc.Stop/Shutdown в
// Execute) обязан звать web.Server.Close() и engine.Stop().
func TestS8_StopProcess_ClosesWebThenStopsEngine(t *testing.T) {
	fc := &fakeWebCloser{}
	fe := &fakeEngineStopper{}
	stopProcess(fc, fe)
	if !fc.closed {
		t.Fatal("stopProcess не вызвал web.Server.Close()")
	}
	if !fe.stopped {
		t.Fatal("stopProcess не вызвал engine.Stop()")
	}
}

// TestS8_StopProcess_ObserverMode_NilSafe — режим наблюдателя (другой процесс уже владеет
// движком): apfService.Execute не поднимает ни eng, ни свой web.Server — оба остаются
// нетипизированным nil на вызове, stopProcess не должен паниковать.
func TestS8_StopProcess_ObserverMode_NilSafe(t *testing.T) {
	stopProcess(nil, nil) // не должен паниковать
}

// TestS8_StopProcess_OnlyEngineNil_StillClosesWeb — гипотетический промежуточный случай
// (движок не поднялся, но Web UI успел стартовать до отказа) — Close() всё равно должен
// сработать, engine.Stop() просто пропускается.
func TestS8_StopProcess_OnlyEngineNil_StillClosesWeb(t *testing.T) {
	fc := &fakeWebCloser{}
	stopProcess(fc, nil)
	if !fc.closed {
		t.Fatal("stopProcess(webSrv, nil) обязан всё равно закрыть web.Server")
	}
}
