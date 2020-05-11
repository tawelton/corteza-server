package service

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/crypto/bcrypt"

	"github.com/cortezaproject/corteza-server/pkg/auditlog"
	internalAuth "github.com/cortezaproject/corteza-server/pkg/auth"
	"github.com/cortezaproject/corteza-server/pkg/eventbus"
	"github.com/cortezaproject/corteza-server/pkg/handle"
	"github.com/cortezaproject/corteza-server/pkg/permissions"
	"github.com/cortezaproject/corteza-server/pkg/rand"
	"github.com/cortezaproject/corteza-server/system/repository"
	"github.com/cortezaproject/corteza-server/system/service/event"
	"github.com/cortezaproject/corteza-server/system/types"
)

type (
	auth struct {
		db  db
		ctx context.Context

		auditlog auditlog.Recorder
		eventbus eventDispatcher

		subscription  authSubscriptionChecker
		credentials   repository.CredentialsRepository
		users         repository.UserRepository
		roles         repository.RoleRepository
		settings      *types.Settings
		notifications AuthNotificationService

		providerValidator func(string) error
		now               func() *time.Time
	}

	AuthService interface {
		With(ctx context.Context) AuthService

		External(profile goth.User) (*types.User, error)
		FrontendRedirectURL() string

		InternalSignUp(input *types.User, password string) (*types.User, error)
		InternalLogin(email string, password string) (*types.User, error)
		SetPassword(userID uint64, newAuthPassword string) error
		ChangePassword(userID uint64, oldPassword, newAuthPassword string) error

		IssueAuthRequestToken(user *types.User) (token string, err error)
		ValidateAuthRequestToken(token string) (user *types.User, err error)
		ValidateEmailConfirmationToken(token string) (user *types.User, err error)
		ExchangePasswordResetToken(token string) (user *types.User, exchangedToken string, err error)
		ValidatePasswordResetToken(token string) (user *types.User, err error)
		SendEmailAddressConfirmationToken(email string) (err error)
		SendPasswordResetToken(email string) (err error)

		CanRegister() error

		LoadRoleMemberships(*types.User) error

		checkPasswordStrength(string) bool
		changePassword(uint64, string) error
	}

	authSubscriptionChecker interface {
		CanRegister(uint) error
	}
)

const (
	credentialsTypePassword                    = "password"
	credentialsTypeEmailAuthToken              = "email-authentication-token"
	credentialsTypeResetPasswordToken          = "password-reset-token"
	credentialsTypeResetPasswordTokenExchanged = "password-reset-token-exchanged"
	credentialsTypeAuthToken                   = "auth-token"

	credentialsTokenLength = 32
)

var (
	reEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

func defaultProviderValidator(provider string) error {
	_, err := goth.GetProvider(provider)
	return err
}

func Auth(ctx context.Context) AuthService {
	return (&auth{
		eventbus:      eventbus.Service(),
		subscription:  CurrentSubscription,
		settings:      CurrentSettings,
		notifications: DefaultAuthNotification,

		auditlog: DefaultAuditLog,

		providerValidator: defaultProviderValidator,

		now: func() *time.Time {
			var now = time.Now()
			return &now
		},
	}).With(ctx)
}

// With returns copy of service with new context
// obsolete approach, will be removed ASAP
func (svc auth) With(ctx context.Context) AuthService {
	db := repository.DB(ctx)
	return &auth{
		db:  db,
		ctx: ctx,

		credentials: repository.Credentials(ctx, db),
		users:       repository.User(ctx, db),
		roles:       repository.Role(ctx, db),

		subscription:      svc.subscription,
		settings:          svc.settings,
		notifications:     svc.notifications,
		eventbus:          svc.eventbus,
		providerValidator: svc.providerValidator,

		auditlog: svc.auditlog,

		now: svc.now,
	}
}

// External func performs login/signup procedures
//
// We fully trust external auth sources (see system/auth/external) to provide a valid & validates
// profile (goth.User) that we use for user discovery and/or creation
//
// Flow
// 1.   check for existing credentials using profile provider & provider's user ID
// 1.1. find existing local -or- "shadow" user
// 1.2. if user exists and is valid, update credentials (last-used-at) and complete the procedure
//
// 2.   check for existing users using email from the profile
// 2.1. validate existing user -or-
// 2.2. create user on-the-fly if it does not exist
// 2.3. create credentials for that social login
//
func (svc auth) External(profile goth.User) (u *types.User, err error) {
	var (
		authProvider = &types.AuthProvider{Provider: profile.Provider}

		aam = authAuditMeta{
			email:           profile.Email,
			credentialsType: profile.Provider,
		}
	)

	return u, svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		if !svc.settings.Auth.External.Enabled {
			return errAuthExternalDisabledByConfig(aam, nil)
		}

		if err = svc.providerValidator(profile.Provider); err != nil {
			return err
		}

		if !reEmail.MatchString(profile.Email) {
			return errAuthProfileWithoutValidEmail(aam, nil)
		}

		if cc, err := svc.credentials.FindByCredentials(profile.Provider, profile.UserID); err == nil {
			// Credentials found, load user
			for _, c := range cc {
				if !c.Valid() {
					continue
				}

				// Add credentials ID for audit log
				aam.credentialsID = c.ID

				if u, err = svc.users.FindByID(c.OwnerID); err != nil {
					if repository.ErrUserNotFound.Eq(err) {
						// Orphaned credentials (no owner)
						// try to auto-fix this by removing credentials and recreating user
						if err = svc.credentials.DeleteByID(c.ID); err != nil {
							return err
						} else {
							goto findByEmail
						}
					}
					return err
				}

				// Add user ID for audit log
				aam.userID = u.ID
				aam.email = u.Email
				svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

				if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeLogin(u, authProvider)); err != nil {
					return err
				}

				if u.Valid() {
					// Valid user, Bingo!
					c.LastUsedAt = svc.now()
					if c, err = svc.credentials.Update(c); err != nil {
						return err
					}

					defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterLogin(u, authProvider))
					svc.rec(svc.ctx, newAuthCredentialsUpdated, aam)
					svc.rec(svc.ctx, newAuthSuccess, aam)
					return nil
				} else {
					// Scenario: linked to an invalid user
					if len(cc) > 1 {
						// try with next credentials
						u = nil
						continue
					}

					return errAuthCredentialsLinkedToInvalidUser(aam, nil)
				}
			}

			// If we could not find anything useful,
			// we can search for user via email
			// (using goto for consistency)
			goto findByEmail
		} else {
			// A serious error occurred, bail out...
			return err
		}

	findByEmail:
		// Reset audit meta data that might got set during credentials check
		aam.email = profile.Email
		aam.userID = 0
		aam.credentialsID = 0

		// Find user via his email
		if u, err = svc.users.FindByEmail(profile.Email); repository.ErrUserNotFound.Eq(err) {
			// @todo check if it is ok to auto-create a user here

			// In case we do not have this email, create a new user
			u = &types.User{
				Email:    profile.Email,
				Name:     profile.Name,
				Username: profile.NickName,
			}

			if !handle.IsValid(profile.NickName) {
				u.Handle = profile.NickName
			}

			if err = svc.CanRegister(); err != nil {
				return errAuthSubscription(aam, err)
			}

			if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeSignup(u, authProvider)); err != nil {
				return err
			}

			if u.Handle == "" {
				createHandle(svc.users, u)
			}

			if u, err = svc.users.Create(u); err != nil {
				return err
			}

			aam.userID = u.ID
			svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

			defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterSignup(u, authProvider))

			svc.rec(svc.ctx, newAuthExternalSignup, aam)

			// Auto-promote first user
			if err = svc.autoPromote(u); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			// User found
			aam.userID = u.ID
			svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

			if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeLogin(u, authProvider)); err != nil {
				return err
			}

			defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterLogin(u, authProvider))

			// If user
			if !u.Valid() {
				return errAuthFailedForDisabledUser(aam, err)
			}

			svc.rec(svc.ctx, newAuthSuccess, aam)
		}

		// If we got to this point, assume that user is authenticated
		// but credentials need to be stored
		c := &types.Credentials{
			Kind:        profile.Provider,
			OwnerID:     u.ID,
			Credentials: profile.UserID,
			LastUsedAt:  svc.now(),
		}

		if c, err = svc.credentials.Create(c); err != nil {
			return err
		}

		aam.credentialsID = c.ID
		svc.rec(svc.ctx, newAuthCredentialsCreated, aam)

		// Owner loaded, carry on.
		return nil
	}))
}

// FrontendRedirectURL - a proxy to frontend redirect url setting
func (svc auth) FrontendRedirectURL() string {
	return svc.settings.Auth.Frontend.Url.Redirect
}

// InternalSignUp protocol
//
// Forgiving but strict: valid existing users get notified
//
// We're accepting the whole user object here and copy all we need to the new user
func (svc auth) InternalSignUp(input *types.User, password string) (u *types.User, err error) {
	var (
		authProvider = &types.AuthProvider{Provider: credentialsTypePassword}

		aam = authAuditMeta{
			email:           input.Email,
			credentialsType: credentialsTypePassword,
		}
	)

	return u, svc.err(svc.ctx, aam, func() error {
		if !svc.settings.Auth.Internal.Enabled || !svc.settings.Auth.Internal.Signup.Enabled {
			return errAuthInternalSignupDisabledByConfig(aam, nil)
		}

		if input == nil || !reEmail.MatchString(input.Email) {
			return errAuthInvalidEmailFormat(aam, nil)
		}

		if len(password) == 0 {
			return errAuthPasswordNotSecure(aam, nil)
		}

		if !handle.IsValid(input.Handle) {
			return errAuthInvalidHandle(aam, nil)
		}

		var eUser *types.User
		eUser, err = svc.users.FindByEmail(input.Email)
		if err == nil && eUser.Valid() {
			var cc types.CredentialsSet
			cc, err = svc.credentials.FindByKind(eUser.ID, credentialsTypePassword)
			if err != nil {
				return err
			}

			if !svc.checkPassword(password, cc) {
				return errAuthInvalidCredentials(aam, nil)
			}

			// We're not actually doing sign-up here - user exists,
			// password is a match, so lets trigger before/after user login events
			if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeLogin(eUser, authProvider)); err != nil {
				return err
			}

			if !eUser.EmailConfirmed {
				err = svc.sendEmailAddressConfirmationToken(eUser)
				if err != nil {
					return err
				}
			}

			defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterLogin(eUser, authProvider))
			u = eUser
			return nil

			// if !svc.settings.internalSignUpSendEmailOnExisting {
			// 	return nil,errors.Wrap(err, "user with this email already exists")
			// }

			// User already exists, but we're nice and we'll send this user an
			// email that will help him to login
			// if !u.Valid() {
			// 	return nil,errors.New("could not validate the user")
			// }
			//
			// return nil,nil
		} else if !repository.ErrUserNotFound.Eq(err) {
			return err
		}

		if err = svc.CanRegister(); err != nil {
			return err
		}

		var nUser = &types.User{
			Email:    input.Email,
			Name:     input.Name,
			Username: input.Username,
			Handle:   input.Handle,

			// Do we need confirmed email?
			EmailConfirmed: !svc.settings.Auth.Internal.Signup.EmailConfirmationRequired,
		}

		if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeSignup(nUser, authProvider)); err != nil {
			return err
		}

		if input.Handle == "" {
			createHandle(svc.users, input)
		}

		// Whitelisted user data to copy
		u, err = svc.users.Create(nUser)

		if err != nil {
			return err
		}

		aam.userID = u.ID
		defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterSignup(u, authProvider))
		svc.rec(svc.ctx, newAuthInternalSignup, aam)

		if err = svc.autoPromote(u); err != nil {
			return err
		}

		if len(password) > 0 {
			err = svc.changePassword(u.ID, password)
			if err != nil {
				return err
			}
		}

		if !u.EmailConfirmed {
			err = svc.sendEmailAddressConfirmationToken(u)
			if err != nil {
				return err
			}

			svc.rec(svc.ctx, newAuthEmailConfirmationTokenSent, aam)
		}

		return nil
	}())
}

// InternalLogin verifies username/password combination in the internal credentials table
//
// Expects plain text password as an input
func (svc auth) InternalLogin(email string, password string) (u *types.User, err error) {
	var (
		authProvider = &types.AuthProvider{Provider: credentialsTypePassword}

		aam = authAuditMeta{
			email:           email,
			credentialsType: credentialsTypePassword,
		}
	)

	return u, svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		if !svc.settings.Auth.Internal.Enabled {
			return errAuthInteralLoginDisabledByConfig(aam, nil)
		}

		if !reEmail.MatchString(email) {
			return errAuthInvalidEmailFormat(aam, nil)
		}

		if len(password) == 0 {
			return errAuthInvalidCredentials(aam, nil)
		}

		var (
			cc types.CredentialsSet
		)

		u, err = svc.users.FindByEmail(email)
		if repository.ErrUserNotFound.Eq(err) {
			return errAuthFailedForUnknownUser(aam, nil)
		}

		if err != nil {
			return err
		}

		// Update audit meta with user ID
		aam.userID = u.ID
		svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

		cc, err = svc.credentials.FindByKind(u.ID, credentialsTypePassword)
		if err != nil {
			return err

		}

		if !svc.checkPassword(password, cc) {
			return errAuthInvalidCredentials(aam, nil)
		}

		if err = svc.eventbus.WaitFor(svc.ctx, event.AuthBeforeLogin(u, authProvider)); err != nil {
			return err
		}

		if !u.Valid() {
			if u.SuspendedAt != nil {
				err = ErrUserSuspended
			} else if u.DeletedAt != nil {
				err = ErrUserDeleted
			} else {
				err = ErrUserInvalid
			}
			u = nil
			return err
		}

		if !u.EmailConfirmed {
			if err = svc.sendEmailAddressConfirmationToken(u); err != nil {
				return err
			}

			return errAuthFailedUnconfirmedEmail(aam, nil)
		}

		defer svc.eventbus.Dispatch(svc.ctx, event.AuthAfterLogin(u, authProvider))
		svc.rec(svc.ctx, newAuthSuccess, aam)
		return nil
	}))
}

// checkPassword returns true if given (encrypted) password matches any of the credentials
func (svc auth) checkPassword(password string, cc types.CredentialsSet) bool {
	// We need only valid credentials (skip deleted, expired)
	for _, c := range cc {
		if !c.Valid() {
			continue
		}

		if len(c.Credentials) == 0 {
			continue
		}

		if bcrypt.CompareHashAndPassword([]byte(c.Credentials), []byte(password)) == nil {
			return true
		}
	}

	return false
}

// SetPassword sets new password for a user
func (svc auth) SetPassword(userID uint64, newAuthPassword string) (err error) {
	var (
		aam = authAuditMeta{
			userID:          userID,
			credentialsType: credentialsTypePassword,
		}
	)

	return svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		if !svc.settings.Auth.Internal.Enabled {
			return errAuthInteralLoginDisabledByConfig(aam, nil)
		}

		if svc.checkPasswordStrength(newAuthPassword) {
			return errAuthPasswordNotSecure(aam, nil)
		}

		if err != svc.changePassword(userID, newAuthPassword) {
			return err
		}

		svc.rec(svc.ctx, newAuthPasswordChanged, aam)
		return nil
	}))
}

// ChangePassword validates old password and changes it with new
func (svc auth) ChangePassword(userID uint64, oldPassword, newAuthPassword string) (err error) {
	var (
		aam = authAuditMeta{
			userID:          userID,
			credentialsType: credentialsTypePassword,
		}
	)

	return svc.db.Transaction(func() error {
		if !svc.settings.Auth.Internal.Enabled {
			return errAuthInteralLoginDisabledByConfig(aam, nil)
		}

		if len(oldPassword) == 0 {
			return errAuthPasswordNotSecure(aam, nil)
		}

		if !svc.checkPasswordStrength(newAuthPassword) {
			return errAuthPasswordNotSecure(aam, nil)
		}

		var (
			cc types.CredentialsSet
		)

		cc, err = svc.credentials.FindByKind(userID, credentialsTypePassword)
		if err != nil {
			return err
		}

		if !svc.checkPassword(oldPassword, cc) {
			return errAuthPasswodResetFailedOldPasswordCheckFailed(aam, nil)
		}

		svc.rec(svc.ctx, newAuthPasswordChangeCheck, aam)

		if err != svc.changePassword(userID, newAuthPassword) {
			return err
		}

		svc.rec(svc.ctx, newAuthPasswordChanged, aam)
		return nil
	})
}

func (svc auth) hashPassword(password string) (hash []byte, err error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func (svc auth) checkPasswordStrength(password string) bool {
	if len(password) <= 4 {
		return false
	}

	return true
}

// ChangePassword (soft) deletes old password entry and creates a new one
//
// Expects hashed password as an input
func (svc auth) changePassword(userID uint64, password string) (err error) {
	var hash []byte
	if hash, err = svc.hashPassword(password); err != nil {
		return
	}

	if err = svc.credentials.DeleteByKind(userID, credentialsTypePassword); err != nil {
		return
	}

	_, err = svc.credentials.Create(&types.Credentials{
		OwnerID:     userID,
		Kind:        credentialsTypePassword,
		Credentials: string(hash),
	})

	return err
}

// IssueAuthRequestToken returns token that can be used for authentication
func (svc auth) IssueAuthRequestToken(user *types.User) (token string, err error) {
	return svc.createUserToken(user, credentialsTypeAuthToken)
}

// ValidateAuthRequestToken returns user that requested auth token
func (svc auth) ValidateAuthRequestToken(token string) (u *types.User, err error) {
	var (
		aam = authAuditMeta{
			credentialsType: credentialsTypeAuthToken,
		}
	)

	return u, svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		u, err = svc.loadUserFromToken(token, credentialsTypeAuthToken)
		if err != nil && u != nil {
			aam.userID = u.ID
			aam.email = u.Email
			svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)
		}
		return err
	}))
}

// ValidateEmailConfirmationToken issues a validation token that can be used for
func (svc auth) ValidateEmailConfirmationToken(token string) (user *types.User, err error) {
	return svc.loadFromTokenAndConfirmEmail(token, credentialsTypeEmailAuthToken)
}

// ValidatePasswordResetToken validates password reset token
func (svc auth) ValidatePasswordResetToken(token string) (user *types.User, err error) {
	return svc.loadFromTokenAndConfirmEmail(token, credentialsTypeEmailAuthToken)
}

// loadFromTokenAndConfirmEmail loads token, confirms user's
func (svc auth) loadFromTokenAndConfirmEmail(token, tokenType string) (u *types.User, err error) {
	var (
		aam = authAuditMeta{
			credentialsType: tokenType,
		}
	)

	return u, svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		if !svc.settings.Auth.Internal.Enabled {
			return errAuthInternalSignupDisabledByConfig(aam, nil)
		}

		u, err = svc.loadUserFromToken(token, tokenType)
		if err != nil {
			return err
		}

		aam.userID = u.ID
		aam.email = u.Email
		svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

		if u.EmailConfirmed {
			return nil
		}

		u.EmailConfirmed = true
		if u, err = svc.users.Update(u); err != nil {
			return err
		}

		svc.rec(svc.ctx, newAuthEmailConfirmed, aam)

		return nil
	}))
}

// ExchangePasswordResetToken exchanges reset password token for a new one and returns it with user info
func (svc auth) ExchangePasswordResetToken(token string) (u *types.User, t string, err error) {
	var (
		aam = authAuditMeta{
			credentialsType: credentialsTypeResetPasswordToken,
		}
	)

	return u, t, svc.err(svc.ctx, aam, svc.db.Transaction(func() error {
		if !svc.settings.Auth.Internal.Enabled || !svc.settings.Auth.Internal.PasswordReset.Enabled {
			return errAuthPasswordResetDisabledByConfig(aam, nil)
		}

		u, err = svc.loadUserFromToken(token, credentialsTypeResetPasswordToken)
		if err != nil {
			return errAuthInvalidToken(aam, err)
		}

		aam.email = u.Email
		aam.userID = u.ID
		svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

		t, err = svc.createUserToken(u, credentialsTypeResetPasswordTokenExchanged)
		if err != nil {
			u = nil
			t = ""
			return errAuthInvalidToken(aam, err)
		}

		return nil
	}))
}

// SendEmailAddressConfirmationToken sends email with email address confirmation token
func (svc auth) SendEmailAddressConfirmationToken(email string) error {
	var (
		aam = authAuditMeta{
			email: email,
		}
	)

	return svc.err(svc.ctx, aam, func() error {
		if !svc.settings.Auth.Internal.Enabled || !svc.settings.Auth.Internal.PasswordReset.Enabled {
			return errAuthPasswordResetDisabledByConfig(aam, nil)
		}

		u, err := svc.users.FindByEmail(email)
		if err != nil {
			return errAuthInvalidToken(aam, nil)
		}

		return svc.sendEmailAddressConfirmationToken(u)
	}())
}

func (svc auth) sendEmailAddressConfirmationToken(u *types.User) (err error) {
	var (
		notificationLang = "en"
		token            string

		aam = authAuditMeta{
			userID:          u.ID,
			email:           u.Email,
			credentialsType: credentialsTypeEmailAuthToken,
		}
	)

	if token, err = svc.createUserToken(u, credentialsTypeEmailAuthToken); err != nil {
		return
	}

	if err = svc.notifications.EmailConfirmation(notificationLang, u.Email, token); err != nil {
		return
	}

	svc.rec(svc.ctx, newAuthEmailConfirmationTokenSent, aam)
	return nil
}

// SendPasswordResetToken sends password reset token to email
func (svc auth) SendPasswordResetToken(email string) error {
	var (
		u *types.User

		aam = authAuditMeta{
			email: email,
		}
	)

	return svc.err(svc.ctx, aam, func() (err error) {
		if !svc.settings.Auth.Internal.Enabled || !svc.settings.Auth.Internal.PasswordReset.Enabled {
			return errAuthPasswordResetDisabledByConfig(aam, nil)
		}

		if u, err = svc.users.FindByEmail(email); err != nil {
			return err
		}

		aam.userID = u.ID
		svc.ctx = internalAuth.SetIdentityToContext(svc.ctx, u)

		if err = svc.sendPasswordResetToken(u); err != nil {
			return err
		}

		svc.rec(svc.ctx, newAuthPasswordResetTokenSent, aam)
		return nil
	}())
}

// CanRegister verifies if user can register
func (svc auth) CanRegister() error {
	if svc.subscription != nil {
		// When we have an active subscription, we need to check
		// if users can register or did this deployment hit
		// it's user-limit
		return svc.subscription.CanRegister(svc.users.Total())
	}

	return nil
}

func (svc auth) sendPasswordResetToken(u *types.User) (err error) {
	var (
		notificationLang = "en"
		token            string

		aam = authAuditMeta{
			userID: u.ID,
			email:  u.Email,
		}
	)

	token, err = svc.createUserToken(u, credentialsTypeResetPasswordToken)
	if err != nil {
		return
	}

	err = svc.notifications.PasswordReset(notificationLang, u.Email, token)
	if err != nil {
		return err
	}

	svc.rec(svc.ctx, newAuthPasswordResetTokenSent, aam)
	return nil
}

func (svc auth) loadUserFromToken(token, kind string) (u *types.User, err error) {
	var (
		aam = authAuditMeta{
			credentialsType: kind,
		}
	)

	credentialsID, credentials := svc.validateToken(token)
	if credentialsID == 0 {
		return nil, errAuthInvalidToken(aam, nil)
	}

	c, err := svc.credentials.FindByID(credentialsID)
	if err == repository.ErrCredentialsNotFound {
		return nil, errAuthInvalidToken(aam, nil)
	}

	aam.credentialsID = credentialsID

	if err != nil {
		return
	}

	if err = svc.credentials.DeleteByID(c.ID); err != nil {
		return
	}

	if !c.Valid() || c.Credentials != credentials {
		return nil, errAuthInvalidToken(aam, nil)
	}

	u, err = svc.users.FindByID(c.OwnerID)
	if err != nil {
		return nil, err
	}

	aam.userID = u.ID
	aam.email = u.Email

	// context will be updated with new identity
	// in the caller fn

	if !u.Valid() {
		return nil, errAuthInvalidCredentials(aam, nil)
	}

	return u, nil
}

func (svc auth) validateToken(token string) (ID uint64, credentials string) {
	// Token = <32 random chars><credentials-id>
	if len(token) <= credentialsTokenLength {
		return
	}

	ID, _ = strconv.ParseUint(token[credentialsTokenLength:], 10, 64)
	if ID == 0 {
		return
	}

	credentials = token[:credentialsTokenLength]
	return
}

// Generates & stores user token
// it returns combined value of token + token ID to help with the lookups
func (svc auth) createUserToken(u *types.User, kind string) (token string, err error) {
	var (
		expiresAt time.Time
		aam       = authAuditMeta{
			email:  u.Email,
			userID: u.ID,
		}
	)

	switch kind {
	case credentialsTypeAuthToken:
		// 15 sec expiration for all tokens that are part of redirection
		expiresAt = svc.now().Add(time.Second * 15)
	default:
		// 1h expiration for all tokens send via email
		expiresAt = svc.now().Add(time.Minute * 60)
	}

	c, err := svc.credentials.Create(&types.Credentials{
		OwnerID:     u.ID,
		Kind:        kind,
		Credentials: string(rand.Bytes(credentialsTokenLength)),
		ExpiresAt:   &expiresAt,
	})

	if err != nil {
		return
	}

	svc.rec(svc.ctx, newAuthTokenIssued, aam)
	token = fmt.Sprintf("%s%d", c.Credentials, c.ID)
	return
}

// Automatically promotes user to administrator if it is the first user in the database
func (svc auth) autoPromote(u *types.User) error {
	if svc.users.Total() > 1 || u.ID == 0 {
		return nil
	}

	if svc.roles == nil {
		// Autopromotion disabled
		return nil
	}

	var (
		roleID = permissions.AdminsRoleID

		aam = authAuditMeta{
			email:  u.Email,
			userID: u.ID,
			roleID: roleID,
		}

		err = svc.roles.MemberAddByID(roleID, u.ID)
	)

	if err != nil {
		return err
	}

	svc.rec(svc.ctx, newAuthAutoPromoted, aam)
	return nil
}

// LoadRoleMemberships loads membership info
func (svc auth) LoadRoleMemberships(u *types.User) error {
	rr, _, err := svc.roles.Find(types.RoleFilter{MemberID: u.ID})
	if err != nil {
		return err
	}

	u.SetRoles(rr.IDs())
	return nil
}
