package auditlog

import (
	"github.com/cortezaproject/corteza-server/pkg/rh"
	"time"
)

type (
	// Any additional data
	// that can be packed with the raised audit event
	Meta map[string]interface{}

	// Severity determinants event severity level
	Severity uint8

	// Standardized data structure for audit log events
	Event struct {
		// Timestamp of the raised event
		Timestamp time.Time `json:"timestamp"`

		// This can contain a series of IP addresses (when proxied)
		// https://en.wikipedia.org/wiki/X-Forwarded-For#Format
		RequestIP string `json:"requestIP"`

		// ID of the user (if not anonymous)
		UserID uint64 `json:"userID,string,omitempty"`

		// Request ID
		RequestID string `json:"requestID"`

		// Event severity
		Severity Severity `json:"severity"`

		// Target system
		Target string `json:"target"`

		// Name of the raised event
		Event string `json:"event"`

		// Description of the event
		Description string `json:"description"`

		// Meta data, target specific
		Meta Meta `json:"meta"`
	}

	Filter struct {
		From      *time.Time `json:"from"`
		To        *time.Time `json:"to"`
		UserID    uint64     `json:"userID"`
		Anonymous bool       `json:"anonymous"`
		Target    string     `json:"target"`

		// Standard paging fields & helpers
		rh.PageFilter
	}
)

const (
	// Not using log/syslog LOG_* constants as they are only
	// available outside windows env.
	Emergency Severity = iota
	Alert
	Critical
	Error
	Warning
	Notice
	Info
	Debug
)
