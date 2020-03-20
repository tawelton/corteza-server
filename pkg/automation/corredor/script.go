package corredor

import (
	"github.com/cortezaproject/corteza-server/pkg/automation"
)

type (
	Runnable interface {
		IsAsync() bool
		GetName() string
		GetSource() string
		GetTimeout() uint32
	}
)

func FromScript(s *automation.Script) *Script {
	// default to the previous ctx timeout value (5s)
	to := uint32(s.Timeout)
	if to == 0 {
		to = 5000
	}

	return &Script{
		Source:  s.Source,
		Name:    s.Name,
		Timeout: to,
		Async:   s.Async,
	}
}
