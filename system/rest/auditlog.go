package rest

import (
	"context"
	"github.com/cortezaproject/corteza-server/pkg/auditlog"
	"github.com/cortezaproject/corteza-server/pkg/rh"
	"github.com/cortezaproject/corteza-server/system/rest/request"
	"github.com/cortezaproject/corteza-server/system/service"
	"github.com/cortezaproject/corteza-server/system/types"
)

type (
	Auditlog struct {
		auditSvc auditlog.Recorder
		userSvc  service.UserService
	}

	// Extend auditlog.Event so we can
	// provide user's email
	auditlogEventPayload struct {
		*auditlog.Event
		UserEmail string `json:"userEmail,omitempty"`
		UserName  string `json:"userName,omitempty"`
	}

	auditlogPayload struct {
		Filter auditlog.Filter         `json:"filter"`
		Set    []*auditlogEventPayload `json:"set"`
	}
)

func (Auditlog) New() *Auditlog {
	return &Auditlog{
		auditSvc: service.DefaultAuditLog,
		userSvc:  service.DefaultUser,
	}
}

func (ctrl *Auditlog) List(ctx context.Context, r *request.AuditlogList) (interface{}, error) {
	ee, f, err := ctrl.auditSvc.Find(ctx, auditlog.Filter{
		From:       r.From,
		To:         r.To,
		UserID:     r.UserID,
		Anonymous:  r.Anonymous,
		Target:     r.Target,
		PageFilter: rh.Paging(r),
	})

	return ctrl.makeFilterPayload(ctx, ee, f, err)
}

func (ctrl Auditlog) makeFilterPayload(ctx context.Context, ee []*auditlog.Event, f auditlog.Filter, err error) (*auditlogPayload, error) {
	if err != nil {
		return nil, err
	}

	var (
		pp = make([]*auditlogEventPayload, len(ee))
	)

	// Remap events to payload structs
	for e := range ee {
		pp[e] = &auditlogEventPayload{Event: ee[e]}
	}

	err = ctrl.userSvc.With(ctx).Preloader(
		func(c chan uint64) {
			for e := range ee {
				c <- ee[e].UserID
			}

			close(c)
		},
		types.UserFilter{
			Deleted:   rh.FilterStateInclusive,
			Suspended: rh.FilterStateInclusive,
		},
		func(u *types.User) error {
			for p := range pp {
				if pp[p].UserID == u.ID {
					pp[p].UserName = u.Name
					pp[p].UserEmail = u.Email
				}
			}

			return nil
		},
	)

	if err != nil {
		return nil, err
	}

	return &auditlogPayload{Filter: f, Set: pp}, nil
}
