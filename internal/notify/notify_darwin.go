package notify

import "os/exec"

func Default() Notifier { return MacOSNotifier{} }

type MacOSNotifier struct{}

func (MacOSNotifier) Notify(title, message string) error {
	script := `display notification "` + escape(message) + `" with title "` + escape(title) + `"`
	return exec.Command("osascript", "-e", script).Run()
}

func escape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '"', '\\':
			out = append(out, '\\', r)
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				continue
			}
			out = append(out, r)
		}
	}
	return string(out)
}
