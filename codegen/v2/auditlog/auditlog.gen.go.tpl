package {{ .Package }}

// This file is auto-generated.
//
// YAML event definitions:
//   {{ .YAML }}
//

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cortezaproject/corteza-server/pkg/auditlog"
)

type (
	{{ $.Service }}AuditMeta struct {
	{{- range $m := $.Meta }}
		{{ $m.Name }} {{ $m.Type }}
	{{- end }}
	}

	{{ $.Service }}AuditEvent struct {
		timestamp time.Time
		target    string
		event     string
		log       string
		severity  auditlog.Severity

		meta authAuditMeta
	}

	{{ $.Service }}Error struct {
		timestamp   time.Time
		target      string
		event       string
		wrap        error
		error 		string
		log         string
		severity    auditlog.Severity

		meta authAuditMeta
	}
)


{{ range $event , $e := $.Events }}
{{ if $e.IsError }}

// {{ camelCase "err" $event  }} returns "{{ $.Target }}.{{ $event  }}" audit event as {{ $e.SeverityConstName }}
//
// This function is auto-generated.
func {{ camelCase "err" $.Service $event  }}(m {{ $.Service }}AuditMeta, err error) *{{ $.Service }}Error {
	var ae = &{{ $.Service }}Error{
		timestamp: time.Now(),
		target:    "{{ $.Target }}",
		event:     "{{ $event }}",
		error:     "{{ $e.Error }}",
		log:       "{{ $e.Log }}",
		severity:  {{ $e.SeverityConstName }},
		meta:      m,
		wrap:      err,
	}

	{{ if $e.Safe }}
	// Wrap into safe error
	ae = {{ camelCase "err" $.Service $e.Safe }}(m, ae)
	{{ end }}

	return ae
}
{{ else }}
// {{ camelCase "new" $event  }} returns "{{ $.Target }}.{{ $event  }}" error
//
// This function is auto-generated.
func {{ camelCase "new" $.Service $event  }}(m {{ $.Service }}AuditMeta) *{{ $.Service }}AuditEvent {
	return &{{ $.Service }}AuditEvent{
		timestamp: time.Now(),
		target:    "{{ $.Target }}",
		event:     "{{ $event }}",
		log:       "{{ $e.Log }}",
		severity:  {{ $e.SeverityConstName }},
		meta:      m,
	}
}
{{ end }}
{{ end }}

// String returns loggable description as string
func (e *{{ $.Service }}AuditEvent) String() string {
	if e.log != "" {
		return e.meta.tr(e.log, nil)
	}

	return e.target + "." + e.event
}

// ToAuditEvent converts {{ $.Service }}AuditEvent to auditlog.Event
func (e *{{ $.Service }}AuditEvent) ToAuditEvent() *auditlog.Event {
	return &auditlog.Event{
		Timestamp:   e.timestamp,
		Severity:    e.severity,
		Target:      e.target,
		Event:       e.event,
		Description: e.String(),
		Meta: auditlog.Meta{
		{{- range $m := $.Meta }}
			"{{ $m.Name }}":   e.meta.{{ $m.Name }},
		{{- end }}
		},
	}
}

// String returns loggable description as string
func (e *{{ $.Service }}Error) String() string {
	if e.log != "" {
		return e.meta.tr(e.log, e.wrap)
	}

	if e.error != "" {
		return e.meta.tr(e.error, e.wrap)
	}

	return e.target + "." + e.event
}

// Error satisfies
func (e {{ $.Service }}Error) Error() string {
	return e.meta.tr(e.error, e.wrap)
}

// Unwrap returns wrapped error
func (e {{ $.Service }}Error) Unwrap() error {
	return e.wrap
}

// Is fn for error equality check
func (e *{{ $.Service }}Error) Is(target error) bool {
	t, ok := target.(*{{ $.Service }}Error)
	if !ok {
		return false
	}

	return t.target == e.target && t.event == e.event
}

// ToAuditEvent converts {{ $.Service }}Error to auditlog.Event
func (e *{{ $.Service }}Error) ToAuditEvent() *auditlog.Event {
	if w, ok := e.Unwrap().(auditlog.AuditableEvent); ok {
		// Unwrap until we get to the lowest auditable event
		return w.ToAuditEvent()
	}

	return &auditlog.Event{
		Timestamp:   e.timestamp,
		Severity:    e.severity,
		Target:      e.target,
		Event:       e.event,
		Description: e.String(),
		Meta: auditlog.Meta{
		{{- range $m := $.Meta }}
			"{{ $m.Name }}":   e.meta.{{ $m.Name }},
		{{- end }}
		},
	}
}

// tr translates string and replaces meta value placeholder with values
func (m {{ $.Service }}AuditMeta) tr(in string, err error) string {
	if err == nil {
		in = strings.ReplaceAll(in, "{err}", "nil")
	} else {
		in = strings.ReplaceAll(in, "{err}", err.Error())
	}

	{{- range $m := $.Meta }}
	in = strings.ReplaceAll(in, "{{"{"}}{{ $m.Name }}}", fmt.Sprintf("%v", m.{{ $m.Name }}))
	{{- end }}

	return in
}

// err() is a service helper function that will wrap non-auth-error and record them
//
// makes work with transevent fn & return values much easier
func (svc {{ $.Service }}) err(ctx context.Context, m {{ $.Service }}AuditMeta, err error) error {
	if err == nil {
		return nil
	}

	var (
		auditErr *{{ $.Service }}Error
		ok bool
	)

	if auditErr, ok = err.(*{{ $.Service }}Error); !ok {
		auditErr = {{ camelCase "err" $.Service "Generic" }}(m, err)
	}

	if svc.auditlog != nil {
		svc.auditlog.Record(ctx, auditErr)
	}

	return auditErr
}

// rec() is a service helper function that records audit events
func (svc {{ $.Service }}) rec(ctx context.Context, ev func(m {{ $.Service }}AuditMeta) *{{ $.Service }}AuditEvent, m {{ $.Service }}AuditMeta) {
	if svc.auditlog != nil {
		svc.auditlog.Record(ctx, ev(m))
	}
}
