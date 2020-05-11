package service

// This file is auto-generated.
//
// YAML event definitions:
//   system/service/auth_auditlog.yaml
//

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cortezaproject/corteza-server/pkg/auditlog"
)

type (
	authAuditMeta struct {
		email           string
		userID          uint64
		credentialsType string
		credentialsID   uint64
		roleID          uint64
	}

	authAuditEvent struct {
		timestamp time.Time
		target    string
		event     string
		log       string
		severity  auditlog.Severity

		meta authAuditMeta
	}

	authError struct {
		timestamp time.Time
		target    string
		event     string
		wrap      error
		error     string
		log       string
		severity  auditlog.Severity

		meta authAuditMeta
	}
)

// newAutoPromoted returns "system.service.auth.autoPromoted" error
//
// This function is auto-generated.
func newAuthAutoPromoted(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "autoPromoted",
		log:       "user {email} auto-promoted to {role}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// newCredentialsCreated returns "system.service.auth.credentialsCreated" error
//
// This function is auto-generated.
func newAuthCredentialsCreated(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "credentialsCreated",
		log:       "new credentials {credentialsType} created",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errCredentialsLinkedToInvalidUser returns "system.service.auth.credentialsLinkedToInvalidUser" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthCredentialsLinkedToInvalidUser(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "credentialsLinkedToInvalidUser",
		error:     "credentials {credentialsType} linked to disabled or deleted user {email}",
		log:       "",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newCredentialsUpdated returns "system.service.auth.credentialsUpdated" error
//
// This function is auto-generated.
func newAuthCredentialsUpdated(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "credentialsUpdated",
		log:       "credentials {credentialsType} updated",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// newEmailConfirmationTokenSent returns "system.service.auth.emailConfirmationTokenSent" error
//
// This function is auto-generated.
func newAuthEmailConfirmationTokenSent(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "emailConfirmationTokenSent",
		log:       "email confirmation notification sent to {email}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// newEmailConfirmed returns "system.service.auth.emailConfirmed" error
//
// This function is auto-generated.
func newAuthEmailConfirmed(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "emailConfirmed",
		log:       "email confirmed",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errExternalDisabledByConfig returns "system.service.auth.externalDisabledByConfig" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthExternalDisabledByConfig(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "externalDisabledByConfig",
		error:     "external authentication (using external authentication provider) is disabled",
		log:       "external authentication is disabled",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newExternalSignup returns "system.service.auth.externalSignup" error
//
// This function is auto-generated.
func newAuthExternalSignup(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "externalSignup",
		log:       "user {email} created after successful external authentication via {credentialsType}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errFailedForDisabledUser returns "system.service.auth.failedForDisabledUser" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthFailedForDisabledUser(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "failedForDisabledUser",
		error:     "",
		log:       "disabled user {email} tried to log-in with {credentialsType}",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	// Wrap into safe error
	ae = errAuthInvalidCredentials(m, ae)

	return ae
}

// errFailedForUnknownUser returns "system.service.auth.failedForUnknownUser" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthFailedForUnknownUser(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "failedForUnknownUser",
		error:     "",
		log:       "unknown user {email} tried to log-in with {credentialsType}",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	// Wrap into safe error
	ae = errAuthInvalidCredentials(m, ae)

	return ae
}

// errFailedUnconfirmedEmail returns "system.service.auth.failedUnconfirmedEmail" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthFailedUnconfirmedEmail(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "failedUnconfirmedEmail",
		error:     "system requires confirmed email before logging in",
		log:       "user {email} tried to log-in with with unconfirmed email",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errGeneric returns "system.service.auth.generic" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthGeneric(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "generic",
		error:     "failed to complete request due to internal error",
		log:       "server failed to complete request due to an error: {err}",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errInteralLoginDisabledByConfig returns "system.service.auth.interalLoginDisabledByConfig" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthInteralLoginDisabledByConfig(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "interalLoginDisabledByConfig",
		error:     "internal login (username/password) is disabled",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newInternalSignup returns "system.service.auth.internalSignup" error
//
// This function is auto-generated.
func newAuthInternalSignup(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "internalSignup",
		log:       "user {email} created",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errInternalSignupDisabledByConfig returns "system.service.auth.internalSignupDisabledByConfig" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthInternalSignupDisabledByConfig(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "internalSignupDisabledByConfig",
		error:     "internal sign-up (username/password) is disabled",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errInvalidCredentials returns "system.service.auth.invalidCredentials" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthInvalidCredentials(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "invalidCredentials",
		error:     "invalid username and password combination",
		log:       "user {email} failed to authenticate with {credentialsType}",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errInvalidEmailFormat returns "system.service.auth.invalidEmailFormat" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthInvalidEmailFormat(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "invalidEmailFormat",
		error:     "invalid email",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errInvalidHandle returns "system.service.auth.invalidHandle" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthInvalidHandle(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "invalidHandle",
		error:     "invalid handle",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errInvalidToken returns "system.service.auth.invalidToken" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthInvalidToken(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "invalidToken",
		error:     "invalid token",
		log:       "",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errPasswodResetFailedOldPasswordCheckFailed returns "system.service.auth.passwodResetFailedOldPasswordCheckFailed" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthPasswodResetFailedOldPasswordCheckFailed(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwodResetFailedOldPasswordCheckFailed",
		error:     "could not change password, old password does not match",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newPasswordChangeCheck returns "system.service.auth.passwordChangeCheck" error
//
// This function is auto-generated.
func newAuthPasswordChangeCheck(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwordChangeCheck",
		log:       "user {email} successfully verified old password",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// newPasswordChanged returns "system.service.auth.passwordChanged" error
//
// This function is auto-generated.
func newAuthPasswordChanged(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwordChanged",
		log:       "user {email} changed his password",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errPasswordNotSecure returns "system.service.auth.passwordNotSecure" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthPasswordNotSecure(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwordNotSecure",
		error:     "provided password is not secure; use longer password with more non-alphanumeric character",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errPasswordResetDisabledByConfig returns "system.service.auth.passwordResetDisabledByConfig" audit event as auditlog.Error
//
// This function is auto-generated.
func errAuthPasswordResetDisabledByConfig(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwordResetDisabledByConfig",
		error:     "password reset is disabled",
		log:       "",
		severity:  auditlog.Error,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newPasswordResetTokenSent returns "system.service.auth.passwordResetTokenSent" error
//
// This function is auto-generated.
func newAuthPasswordResetTokenSent(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "passwordResetTokenSent",
		log:       "password reset token sent to {email}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// errProfileWithoutValidEmail returns "system.service.auth.profileWithoutValidEmail" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthProfileWithoutValidEmail(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "profileWithoutValidEmail",
		error:     "external authentication provider returned profile without valid email",
		log:       "external authentication provider {credentialsType} returned profile without valid email",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// errSubscription returns "system.service.auth.subscription" audit event as auditlog.Warning
//
// This function is auto-generated.
func errAuthSubscription(m authAuditMeta, err error) *authError {
	var ae = &authError{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "subscription",
		error:     "{err}",
		log:       "{err}",
		severity:  auditlog.Warning,
		meta:      m,
		wrap:      err,
	}

	return ae
}

// newSuccess returns "system.service.auth.success" error
//
// This function is auto-generated.
func newAuthSuccess(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "success",
		log:       "user {email} successfully authenticated with {credentialsType}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// newTokenIssued returns "system.service.auth.tokenIssued" error
//
// This function is auto-generated.
func newAuthTokenIssued(m authAuditMeta) *authAuditEvent {
	return &authAuditEvent{
		timestamp: time.Now(),
		target:    "system.service.auth",
		event:     "tokenIssued",
		log:       "token {credentialsType} issued for {email}",
		severity:  auditlog.Info,
		meta:      m,
	}
}

// String returns loggable description as string
func (e *authAuditEvent) String() string {
	if e.log != "" {
		return e.meta.tr(e.log, nil)
	}

	return e.target + "." + e.event
}

// ToAuditEvent converts authAuditEvent to auditlog.Event
func (e *authAuditEvent) ToAuditEvent() *auditlog.Event {
	return &auditlog.Event{
		Timestamp:   e.timestamp,
		Severity:    e.severity,
		Target:      e.target,
		Event:       e.event,
		Description: e.String(),
		Meta: auditlog.Meta{
			"email":           e.meta.email,
			"userID":          e.meta.userID,
			"credentialsType": e.meta.credentialsType,
			"credentialsID":   e.meta.credentialsID,
			"roleID":          e.meta.roleID,
		},
	}
}

// String returns loggable description as string
func (e *authError) String() string {
	if e.log != "" {
		return e.meta.tr(e.log, e.wrap)
	}

	if e.error != "" {
		return e.meta.tr(e.error, e.wrap)
	}

	return e.target + "." + e.event
}

// Error satisfies
func (e authError) Error() string {
	return e.meta.tr(e.error, e.wrap)
}

// Unwrap returns wrapped error
func (e authError) Unwrap() error {
	return e.wrap
}

// Is fn for error equality check
func (e *authError) Is(target error) bool {
	t, ok := target.(*authError)
	if !ok {
		return false
	}

	return t.target == e.target && t.event == e.event
}

// ToAuditEvent converts authError to auditlog.Event
func (e *authError) ToAuditEvent() *auditlog.Event {
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
			"email":           e.meta.email,
			"userID":          e.meta.userID,
			"credentialsType": e.meta.credentialsType,
			"credentialsID":   e.meta.credentialsID,
			"roleID":          e.meta.roleID,
		},
	}
}

// tr translates string and replaces meta value placeholder with values
func (m authAuditMeta) tr(in string, err error) string {
	if err == nil {
		in = strings.ReplaceAll(in, "{err}", "nil")
	} else {
		in = strings.ReplaceAll(in, "{err}", err.Error())
	}
	in = strings.ReplaceAll(in, "{email}", fmt.Sprintf("%v", m.email))
	in = strings.ReplaceAll(in, "{userID}", fmt.Sprintf("%v", m.userID))
	in = strings.ReplaceAll(in, "{credentialsType}", fmt.Sprintf("%v", m.credentialsType))
	in = strings.ReplaceAll(in, "{credentialsID}", fmt.Sprintf("%v", m.credentialsID))
	in = strings.ReplaceAll(in, "{roleID}", fmt.Sprintf("%v", m.roleID))

	return in
}

// err() is a service helper function that will wrap non-auth-error and record them
//
// makes work with transevent fn & return values much easier
func (svc auth) err(ctx context.Context, m authAuditMeta, err error) error {
	if err == nil {
		return nil
	}

	var (
		auditErr *authError
		ok       bool
	)

	if auditErr, ok = err.(*authError); !ok {
		auditErr = errAuthGeneric(m, err)
	}

	if svc.auditlog != nil {
		svc.auditlog.Record(ctx, auditErr)
	}

	return auditErr
}

// rec() is a service helper function that records audit events
func (svc auth) rec(ctx context.Context, ev func(m authAuditMeta) *authAuditEvent, m authAuditMeta) {
	if svc.auditlog != nil {
		svc.auditlog.Record(ctx, ev(m))
	}
}
