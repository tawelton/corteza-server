package auditlog

import (
	"context"
	"github.com/cortezaproject/corteza-server/pkg/api"
	"github.com/cortezaproject/corteza-server/pkg/auth"
	"github.com/go-chi/chi/middleware"

	"go.uber.org/zap"
)

type (
	service struct {
		// where the audit log records are kept
		repo recordKeeper

		// Also write audit events here
		tee *zap.Logger

		// logger for repository errors
		logger *zap.Logger
	}

	AuditableEvent interface {
		ToAuditEvent() *Event
	}

	Recorder interface {
		Record(context.Context, AuditableEvent)
		Find(context.Context, Filter) (EventSet, Filter, error)
	}

	recordKeeper interface {
		Record(context.Context, *Event) error
		Find(context.Context, Filter) (EventSet, Filter, error)
	}
)

// NewService initializes auditlog service
//
func NewService(r recordKeeper, logger, tee *zap.Logger) (svc *service) {
	if tee == nil {
		tee = zap.NewNop()
	}

	svc = &service{
		tee:    tee,
		logger: logger,
		repo:   r,
	}

	return
}

func (svc service) Record(ctx context.Context, e AuditableEvent) {
	var (
		ae  = extractFromContext(ctx, e.ToAuditEvent())
		log = svc.logger
	)

	zlf := []zap.Field{
		zap.String("event", ae.Event),
		zap.String("target", ae.Target),
		zap.Time("timestamp", ae.Timestamp),
		zap.String("requestIP", ae.RequestIP),
		zap.String("requestID: ", ae.RequestID),
		zap.Uint64("userID", ae.UserID),
	}

	for k, v := range ae.Meta {
		zlf = append(zlf, zap.Any("meta."+k, v))
	}

	log.Debug(ae.Description, zlf...)

	if err := svc.repo.Record(ctx, ae); err != nil {
		log.With(zap.Error(err)).Error("could not record audit event")
	}
}

func (svc service) Find(ctx context.Context, flt Filter) (EventSet, Filter, error) {
	return svc.repo.Find(ctx, flt)
}

func extractFromContext(ctx context.Context, e *Event) *Event {
	// IP from the request
	e.RequestIP = api.RemoteAddrFromContext(ctx)

	// Relies on chi's middleware to get to the request ID
	// This does not hurt us for now.
	e.RequestID = middleware.GetReqID(ctx)

	// uses pkg/auth to extract stored identity from context
	e.UserID = auth.GetIdentityFromContext(ctx).Identity()

	return e
}
