package request

/*
	Hello! This file is auto-generated from `docs/src/spec.json`.

	For development:
	In order to update the generated files, edit this file under the location,
	add your struct fields, imports, API definitions and whatever you want, and:

	1. run [spec](https://github.com/titpetric/spec) in the same folder,
	2. run `./_gen.php` in this folder.

	You may edit `auditlog.go`, `auditlog.util.go` or `auditlog_test.go` to
	implement your API calls, helper functions and tests. The file `auditlog.go`
	is only generated the first time, and will not be overwritten if it exists.
*/

import (
	"io"
	"strings"

	"encoding/json"
	"mime/multipart"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"

	"time"
)

var _ = chi.URLParam
var _ = multipart.FileHeader{}

// AuditlogList request parameters
type AuditlogList struct {
	hasFrom bool
	rawFrom string
	From    *time.Time

	hasTo bool
	rawTo string
	To    *time.Time

	hasTarget bool
	rawTarget string
	Target    string

	hasUserID bool
	rawUserID string
	UserID    uint64 `json:",string"`

	hasAnonymous bool
	rawAnonymous string
	Anonymous    bool

	hasLimit bool
	rawLimit string
	Limit    uint

	hasOffset bool
	rawOffset string
	Offset    uint

	hasPage bool
	rawPage string
	Page    uint

	hasPerPage bool
	rawPerPage string
	PerPage    uint
}

// NewAuditlogList request
func NewAuditlogList() *AuditlogList {
	return &AuditlogList{}
}

// Auditable returns all auditable/loggable parameters
func (r AuditlogList) Auditable() map[string]interface{} {
	var out = map[string]interface{}{}

	out["from"] = r.From
	out["to"] = r.To
	out["target"] = r.Target
	out["userID"] = r.UserID
	out["anonymous"] = r.Anonymous
	out["limit"] = r.Limit
	out["offset"] = r.Offset
	out["page"] = r.Page
	out["perPage"] = r.PerPage

	return out
}

// Fill processes request and fills internal variables
func (r *AuditlogList) Fill(req *http.Request) (err error) {
	if strings.ToLower(req.Header.Get("content-type")) == "application/json" {
		err = json.NewDecoder(req.Body).Decode(r)

		switch {
		case err == io.EOF:
			err = nil
		case err != nil:
			return errors.Wrap(err, "error parsing http request body")
		}
	}

	if err = req.ParseForm(); err != nil {
		return err
	}

	get := map[string]string{}
	post := map[string]string{}
	urlQuery := req.URL.Query()
	for name, param := range urlQuery {
		get[name] = string(param[0])
	}
	postVars := req.Form
	for name, param := range postVars {
		post[name] = string(param[0])
	}

	if val, ok := get["from"]; ok {
		r.hasFrom = true
		r.rawFrom = val

		if r.From, err = parseISODatePtrWithErr(val); err != nil {
			return err
		}
	}
	if val, ok := get["to"]; ok {
		r.hasTo = true
		r.rawTo = val

		if r.To, err = parseISODatePtrWithErr(val); err != nil {
			return err
		}
	}
	if val, ok := get["target"]; ok {
		r.hasTarget = true
		r.rawTarget = val
		r.Target = val
	}
	if val, ok := get["userID"]; ok {
		r.hasUserID = true
		r.rawUserID = val
		r.UserID = parseUInt64(val)
	}
	if val, ok := get["anonymous"]; ok {
		r.hasAnonymous = true
		r.rawAnonymous = val
		r.Anonymous = parseBool(val)
	}
	if val, ok := get["limit"]; ok {
		r.hasLimit = true
		r.rawLimit = val
		r.Limit = parseUint(val)
	}
	if val, ok := get["offset"]; ok {
		r.hasOffset = true
		r.rawOffset = val
		r.Offset = parseUint(val)
	}
	if val, ok := get["page"]; ok {
		r.hasPage = true
		r.rawPage = val
		r.Page = parseUint(val)
	}
	if val, ok := get["perPage"]; ok {
		r.hasPerPage = true
		r.rawPerPage = val
		r.PerPage = parseUint(val)
	}

	return err
}

var _ RequestFiller = NewAuditlogList()

// HasFrom returns true if from was set
func (r *AuditlogList) HasFrom() bool {
	return r.hasFrom
}

// RawFrom returns raw value of from parameter
func (r *AuditlogList) RawFrom() string {
	return r.rawFrom
}

// GetFrom returns casted value of  from parameter
func (r *AuditlogList) GetFrom() *time.Time {
	return r.From
}

// HasTo returns true if to was set
func (r *AuditlogList) HasTo() bool {
	return r.hasTo
}

// RawTo returns raw value of to parameter
func (r *AuditlogList) RawTo() string {
	return r.rawTo
}

// GetTo returns casted value of  to parameter
func (r *AuditlogList) GetTo() *time.Time {
	return r.To
}

// HasTarget returns true if target was set
func (r *AuditlogList) HasTarget() bool {
	return r.hasTarget
}

// RawTarget returns raw value of target parameter
func (r *AuditlogList) RawTarget() string {
	return r.rawTarget
}

// GetTarget returns casted value of  target parameter
func (r *AuditlogList) GetTarget() string {
	return r.Target
}

// HasUserID returns true if userID was set
func (r *AuditlogList) HasUserID() bool {
	return r.hasUserID
}

// RawUserID returns raw value of userID parameter
func (r *AuditlogList) RawUserID() string {
	return r.rawUserID
}

// GetUserID returns casted value of  userID parameter
func (r *AuditlogList) GetUserID() uint64 {
	return r.UserID
}

// HasAnonymous returns true if anonymous was set
func (r *AuditlogList) HasAnonymous() bool {
	return r.hasAnonymous
}

// RawAnonymous returns raw value of anonymous parameter
func (r *AuditlogList) RawAnonymous() string {
	return r.rawAnonymous
}

// GetAnonymous returns casted value of  anonymous parameter
func (r *AuditlogList) GetAnonymous() bool {
	return r.Anonymous
}

// HasLimit returns true if limit was set
func (r *AuditlogList) HasLimit() bool {
	return r.hasLimit
}

// RawLimit returns raw value of limit parameter
func (r *AuditlogList) RawLimit() string {
	return r.rawLimit
}

// GetLimit returns casted value of  limit parameter
func (r *AuditlogList) GetLimit() uint {
	return r.Limit
}

// HasOffset returns true if offset was set
func (r *AuditlogList) HasOffset() bool {
	return r.hasOffset
}

// RawOffset returns raw value of offset parameter
func (r *AuditlogList) RawOffset() string {
	return r.rawOffset
}

// GetOffset returns casted value of  offset parameter
func (r *AuditlogList) GetOffset() uint {
	return r.Offset
}

// HasPage returns true if page was set
func (r *AuditlogList) HasPage() bool {
	return r.hasPage
}

// RawPage returns raw value of page parameter
func (r *AuditlogList) RawPage() string {
	return r.rawPage
}

// GetPage returns casted value of  page parameter
func (r *AuditlogList) GetPage() uint {
	return r.Page
}

// HasPerPage returns true if perPage was set
func (r *AuditlogList) HasPerPage() bool {
	return r.hasPerPage
}

// RawPerPage returns raw value of perPage parameter
func (r *AuditlogList) RawPerPage() string {
	return r.rawPerPage
}

// GetPerPage returns casted value of  perPage parameter
func (r *AuditlogList) GetPerPage() uint {
	return r.PerPage
}
