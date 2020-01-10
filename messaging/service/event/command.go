package event

import (
	"github.com/cortezaproject/corteza-server/messaging/types"
	"github.com/cortezaproject/corteza-server/pkg/eventbus"
)

// Match returns false if given conditions do not match event & resource internals
func (res commandBase) Match(c eventbus.ConstraintMatcher) bool {
	return channelMatch(res.channel, c, commandMatch(res.command, c))
}

// Handles command matchers
func commandMatch(r *types.Command, c eventbus.ConstraintMatcher) bool {
	switch c.Name() {
	case "command", "command.name":
		return r != nil && c.Match(r.Name)
	}

	return false
}
