// domain_sticky.go — расширение StickySessionManager для domain-level sticky sessions.
// tunnel-architect: при переключении узла важно, чтобы активные сессии (например,
// банк, Google Auth) оставались на том же узле до завершения операции.
//
// Состояние (domainStore/currentNodeID) — ПОЛЯ StickySessionManager (см. sticky.go), а
// не package-level переменные: домен/узел, к которому привязана сессия, принадлежит
// конкретному менеджеру, а не пакету целиком. См. комментарий у полей в sticky.go.
package session

import (
	"time"
)

// domainSession хранит привязку домена к конкретному узлу.
type domainSession struct {
	nodeID    string
	expiresAt time.Time
}

// domainStickyTTL — время жизни domain-sticky записи после последнего обращения.
const domainStickyTTL = 30 * time.Minute

// SetCurrentNode сохраняет ID текущего активного узла.
// Вызывается engine при успешном подключении.
func (s *StickySessionManager) SetCurrentNode(nodeID string) {
	s.currentNodeMu.Lock()
	s.currentNodeID = nodeID
	s.currentNodeMu.Unlock()
}

// GetCurrentNode возвращает ID текущего активного узла.
func (s *StickySessionManager) GetCurrentNode() string {
	s.currentNodeMu.RLock()
	defer s.currentNodeMu.RUnlock()
	return s.currentNodeID
}

// PinDomain привязывает домен к текущему активному узлу.
// Вызывается при создании нового соединения к домену.
func (s *StickySessionManager) PinDomain(domain string) {
	nodeID := s.GetCurrentNode()
	if nodeID == "" {
		return
	}
	s.domainMu.Lock()
	s.domainStore[domain] = domainSession{
		nodeID:    nodeID,
		expiresAt: time.Now().Add(domainStickyTTL),
	}
	s.domainMu.Unlock()
}

// GetPinnedNode возвращает ID узла, к которому привязан домен.
// Возвращает "" если привязки нет или она истекла.
func (s *StickySessionManager) GetPinnedNode(domain string) string {
	s.domainMu.RLock()
	sess, ok := s.domainStore[domain]
	s.domainMu.RUnlock()

	if !ok || time.Now().After(sess.expiresAt) {
		return ""
	}
	return sess.nodeID
}

// CleanExpiredDomainSessions удаляет истекшие domain-sticky записи.
// Вызывается engine периодически (каждые N секунд) для освобождения памяти.
func (s *StickySessionManager) CleanExpiredDomainSessions() {
	now := time.Now()
	s.domainMu.Lock()
	for domain, sess := range s.domainStore {
		if now.After(sess.expiresAt) {
			delete(s.domainStore, domain)
		}
	}
	s.domainMu.Unlock()
}

// ClearDomainSticky удаляет все domain-sticky привязки.
// Вызывается engine при явной смене узла пользователем или при отключении.
func (s *StickySessionManager) ClearDomainSticky() {
	s.domainMu.Lock()
	s.domainStore = make(map[string]domainSession)
	s.domainMu.Unlock()
}

// DomainStickyCount возвращает количество активных domain-sticky записей.
// Используется для диагностики (логирование в engine).
func (s *StickySessionManager) DomainStickyCount() int {
	s.domainMu.RLock()
	defer s.domainMu.RUnlock()
	return len(s.domainStore)
}
