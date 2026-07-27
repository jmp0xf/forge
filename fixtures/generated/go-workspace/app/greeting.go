package greeting

import "example.com/forge-fixtures/go-workspace/message"

func Greeting() string {
	return message.Text() + " from workspace"
}
