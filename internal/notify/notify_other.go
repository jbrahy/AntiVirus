//go:build !darwin

package notify

func Default() Notifier { return NoopNotifier{} }

// NoopNotifier is used on platforms with no desktop-notification integration
// yet. avtool still queues every match for `avtool review` either way.
type NoopNotifier struct{}

func (NoopNotifier) Notify(title, message string) error { return nil }
