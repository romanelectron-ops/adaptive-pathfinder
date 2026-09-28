//go:build !windows

package hotkey

func register(combo string, onTrigger func()) (Manager, error) {
	return nil, ErrUnsupported
}
