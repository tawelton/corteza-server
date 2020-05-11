package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/squirrel"
	"github.com/cortezaproject/corteza-server/pkg/auditlog"
	"github.com/cortezaproject/corteza-server/pkg/rh"
	"github.com/titpetric/factory"
	"time"
)

type (
	// Basic mysql storage backend for audit log events
	//
	// this does not follow the usual (one) repository pattern
	// but tries to move towards multi-flavoured repository support
	mysql struct {
		dbh *factory.DB
		tbl string
	}

	event struct {
		Timestamp   time.Time       `db:"ts"`
		RequestIP   string          `db:"request_ip"`
		RequestID   string          `db:"request_id"`
		Severity    int             `db:"severity"`
		UserID      uint64          `db:"user_id"`
		Target      string          `db:"target"`
		Event       string          `db:"event"`
		Description string          `db:"description"`
		Meta        json.RawMessage `db:"meta"`
	}
)

func Mysql(db *factory.DB, tbl string) *mysql {
	return &mysql{
		// connection
		dbh: db,

		// table to store the data
		tbl: tbl,
	}
}

func (r *mysql) db() *factory.DB {
	return r.dbh
}

func (r mysql) columns() []string {
	return []string{
		"ts",
		"user_id",
		"request_ip",
		"request_id",
		"target",
		"event",
		"severity",
		"description",
		"meta",
	}
}

func (r mysql) query() squirrel.SelectBuilder {
	return squirrel.
		Select(r.columns()...).
		From(r.tbl)
}

func (r *mysql) Find(ctx context.Context, flt auditlog.Filter) (set auditlog.EventSet, f auditlog.Filter, err error) {
	f = flt

	query := r.query()

	if f.From != nil {
		query = query.Where(squirrel.GtOrEq{"ts": f.From})
	}

	if f.To != nil {
		query = query.Where(squirrel.LtOrEq{"ts": f.To})
	}

	if f.Anonymous {
		query = query.Where(squirrel.Eq{"user_id": 0})
	} else if f.UserID > 0 {
		query = query.Where(squirrel.Eq{"user_id": f.UserID})
	}

	if f.Target != "" {
		query = query.Where(squirrel.Eq{"target": f.Target})
	}

	query = query.OrderBy("ts DESC")

	results := make([]*event, 0)
	if err = rh.FetchPaged(r.db(), query, f.PageFilter, &results); err != nil {
		return nil, f, err
	}

	set = make(auditlog.EventSet, len(results))
	for i, r := range results {
		set[i] = &auditlog.Event{
			Timestamp:   r.Timestamp,
			RequestIP:   r.RequestIP,
			UserID:      r.UserID,
			RequestID:   r.RequestID,
			Severity:    auditlog.Severity(r.Severity),
			Target:      r.Target,
			Event:       r.Event,
			Description: r.Description,
		}

		if err = json.Unmarshal(r.Meta, &set[i].Meta); err != nil {
			return nil, f, err
		}
	}

	return set, f, nil
}

// Record stores audit event
func (r *mysql) Record(ctx context.Context, e *auditlog.Event) error {
	m, err := json.Marshal(e.Meta)
	if err != nil {
		return fmt.Errorf("could not format auditlog event: %w", err)
	}

	return r.dbh.With(ctx).InsertIgnore(r.tbl, event{
		Timestamp:   e.Timestamp,
		RequestIP:   e.RequestIP,
		RequestID:   e.RequestID,
		Severity:    int(e.Severity),
		UserID:      e.UserID,
		Target:      e.Target,
		Event:       e.Event,
		Description: e.Description,
		Meta:        m,
	})
}
