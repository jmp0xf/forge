package embedded

import _ "embed"

//go:embed assets/message.txt
var message string

func Message() string {
	return message
}
