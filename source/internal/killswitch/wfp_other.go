//go:build !windows || !(amd64 || arm64)

package killswitch

// Заглушка WFP-бэкенда: не-Windows либо 32-битная Windows.
//
// B-0403 · R-9: на windows/386 раскладка FWPM-структур из wfp_windows.go неверна (там модель
// LLP64 с 8-байтным указателем). Собрать её туда — значит отправлять в ядро мусорные фильтры
// фаервола. Поэтому на таких целях WFP просто отсутствует, а capability-гейт R-1.2 честно не
// пустит netsh в VPN-режим — пользователь увидит внятный отказ вместо тихо неработающей защиты.

// newWFPKS — WFP-бэкенд на этой цели недоступен.
func newWFPKS() (KillSwitch, bool) { return nil, false }

// wfpUsable — WFP на этой цели не существует.
func wfpUsable() bool { return false }
