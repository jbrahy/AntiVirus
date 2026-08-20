package notify

type Notifier interface {
	Notify(title, message string) error
}
