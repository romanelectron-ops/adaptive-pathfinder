package engine

import (
	"context"
	"errors"

	"github.com/apf/adaptive-pathfinder/internal/models"
	"github.com/apf/adaptive-pathfinder/internal/singbox"
)

// Классы отказа подключения (TZ_SINGBOX_HOTSWITCH_WINDOWS_v1.0 §8, этапы A1-A3).
//
// Корень (RCA #2, «5 почему»): в модели отказов не было класса «сбой не по вине узла» — все
// failReason* описывают узел, и ЛЮБАЯ ошибка connectNode превращалась в recordNodeFailure
// (Score=0, на диск) + markNodeFailed (исключение на 10 мин). Живой лог ПК 2026-09-21: ОС
// создавала процесс sing-box.exe десятки секунд, порт не открывался за срок — и шесть узлов
// подряд (score 0.84-0.85, TCP жив) получили штраф за то, что случилось ДО чтения их данных.
//
// Три класса:
//   - failureNode — отказ узла: конфиг из его данных не собрался или sing-box его отверг, адрес
//     узла не резолвится. Штраф + переход к следующему кандидату (как было).
//   - failureLocal — сбой этой машины: порт занят, Kill Switch не применился, конфиг не
//     записан, ОС не создала процесс, порт не открылся за срок. Узел не штрафуется, перебор
//     ОСТАНАВЛИВАЕТСЯ: следующий кандидат упал бы так же (A2; в инциденте — шесть раз подряд
//     одна и та же ошибка). Повтор — через обычный ре-арминг.
//   - failureNoJudgement — отменили НАС (Stop/Restart/Disconnect). Ни штрафа, ни продолжения.
type connectFailureClass int

const (
	failureNode connectFailureClass = iota
	failureLocal
	failureNoJudgement
)

var (
	errLocalConnect = errors.New("сбой подключения на стороне этой машины")
	errNodeConnect  = errors.New("отказ узла")
)

// classedConnectError — ошибка с классом; текст исходной ошибки не меняется (по нему читают
// журнал и lastRollback), а Unwrap отдаёт и класс, и причину.
type classedConnectError struct {
	class error
	err   error
}

func (e *classedConnectError) Error() string   { return e.err.Error() }
func (e *classedConnectError) Unwrap() []error { return []error{e.class, e.err} }

// markLocalFailure помечает ошибку локальной — если она ещё не классифицирована как отказ узла
// (например, неразрешимый адрес узла, пришедший через стадию Kill Switch).
func markLocalFailure(err error) error {
	if err == nil || errors.Is(err, errNodeConnect) || errors.Is(err, errLocalConnect) {
		return err
	}
	return &classedConnectError{class: errLocalConnect, err: err}
}

// markNodeFailure явно помечает ошибку отказом узла — чтобы последующая стадийная разметка
// (markLocalFailure в rollbackConnectionAttempt) её не перекрасила.
func markNodeFailure(err error) error {
	if err == nil {
		return nil
	}
	return &classedConnectError{class: errNodeConnect, err: err}
}

// rotateAfterStartTimeout — страховка от зацикливания (консилиум приёмки этапа A, правка M2).
//
// Локальный сбой останавливает перебор, повтор идёт ре-армингом — и берёт тот же верхний узел.
// Если бы «порт не открылся за срок» когда-нибудь вызывал именно узел (механизма не найдено:
// исходящие соединения ленивые, адрес узла закреплён IP заранее — R-8, но процесс в этот момент
// уже исполнял конфиг узла), поиск застрял бы на нём навсегда — класс дефекта «мёртвый узел
// держал без интернета». Поэтому на ЭТОМ подклассе узел мягко уходит из ближайшего выбора
// (markNodeFailed: в памяти, 10 мин), но без recordNodeFailure — Score и nodes_cache.json не
// трогаются, то есть вред RCA #2 (стойкий штраф невиновных) не возвращается. Цена при настоящем
// сбое машины — не больше одного исключённого узла на цикл ре-арминга.
func (e *Engine) rotateAfterStartTimeout(n *models.Node, err error) {
	if n != nil && errors.Is(err, singbox.ErrReadyTimeout) {
		e.markNodeFailed(n.ID)
	}
}

// classifyConnectFailure — класс отказа подключения.
//
// Порядок важен: сначала «отменили нас» (context.Canceled живёт и внутри локальных ошибок
// старта sing-box — прерванный Stop'ом запуск), затем локальный класс, иначе — узел.
// context.DeadlineExceeded намеренно НЕ «без суждения»: у движка нет своего дедлайна на
// подключение, истёкший срок пришёл бы из чужой пробы и судится по своему классу.
//
// «Не распознано» = отказ узла, как и было до этапа A: так перебор кандидатов продолжается,
// и неизвестная ошибка плохого узла не может заклинить поиск на нём (см. classifyEarlyExit).
func classifyConnectFailure(err error) connectFailureClass {
	switch {
	case err == nil:
		return failureNode
	case errors.Is(err, context.Canceled):
		return failureNoJudgement
	case errors.Is(err, errNodeConnect):
		return failureNode
	case errors.Is(err, errLocalConnect), errors.Is(err, singbox.ErrLocalStart):
		return failureLocal
	default:
		return failureNode
	}
}
