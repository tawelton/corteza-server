package auditlog

//func logEvent(ctx context.Context, e AuditEvent) *zap.Logger {
//	var (
//		identity = auth.GetIdentityFromContext(ctx)
//		log      = logger.AddRequestID(ctx, logger.Default())
//	)
//
//	return logger.Default().Named(e.Target())
//}

/*

Rationale

We need a tight, unified set of error and standardised systm


classes
 - authentication
 - permissions
 - create
 - read
 - update
 - delete



log/
	events.go
	events.yaml
	  auth:
		- authenticated:        Authenticated
		- authenticationFailed: Authentication failed
          level: error
		- credentialsUpdated:   Credentials updated
		- tokenIssued:          Authentication token issued
		- tokenUsed:            Authentication token used
		- tokenUseFailed:       Failed to use authentication token
          level: error

	  user:
		- created
		- updated
		- deleted
		- suspended
		- unsuspended
		- deleted
		- undeleted
	  role:
        - created
        - updated
        - archived
        - unarchived
        - deleted
        - undeleted
        - memberAdd
        - MemberRemove
        - grant
        - revoke


security event
	SHA-1
	Timestamp

	Context:
		IP
		request ID
		UA
		Version/commit

	Actor:



	/system/user
		created
		updated
		authenticated
		authentication-failed		wrong password?
		credentials-updated			password changed?
		authentication-token-issued
		authentication-token-used
		suspended
		unsuspended
		deleted
		undeleted


	/system/role
		created
		updated
		archived
		unarchived
		deleted
		undeleted
		add member
		remove member
		permissions grant
		permissions revoke


User <USER> created
User <USER> registered
User <USER> updated
User <USER> authenticated with <CREDENTIALS-TYPE>
User <USER> authenticated with <PROVIDER> ID
User <USER> suspended
Role <ROLE> added to user <USER>
Role <ROLE> removed from user <USER>
Role <ROLE> restored
Role <ROLE> deleted
Role <ROLE> unarchived
Role <ROLE> was granted <ALLOW> permission for <ACTION> on <RESOURCE> from <USER>


*/
