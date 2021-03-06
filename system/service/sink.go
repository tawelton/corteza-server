package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	internalAuth "github.com/cortezaproject/corteza-server/pkg/auth"
	"github.com/cortezaproject/corteza-server/pkg/eventbus"
	"github.com/cortezaproject/corteza-server/pkg/logger"
	"github.com/cortezaproject/corteza-server/system/service/event"
	"github.com/cortezaproject/corteza-server/system/types"
)

type (
	sink struct {
		logger     *zap.Logger
		signer     internalAuth.Signer
		eventbus   sinkEventDispatcher
		isMonolith bool
	}

	SinkRequestUrlParams struct {
		// Expect sink request to be of this method
		Method string `json:"mtd,omitempty"`

		// OpUsed as an identifier, no validation of request params
		Origin string `json:"origin,omitempty"`

		// If set
		Expires *time.Time `json:"exp,omitempty"`

		// When set it enables body processing (but limits it to that size!)
		MaxBodySize int64 `json:"mbs,omitempty"`

		// Acceptable content type
		ContentType string `json:"ct,omitempty"`
	}

	sinkEventDispatcher interface {
		WaitFor(ctx context.Context, ev eventbus.Event) (err error)
	}
)

const (
	ErrSinkContentTypeUnsupported  serviceError = "SinkUnsupportedContentType"
	ErrSinkContentProcessingFailed serviceError = "SinkProcessFailed"

	SinkContentTypeMail = "message/rfc822"

	SinkSignUrlParamName      = "__sign"
	SinkSignUrlParamDelimiter = "_"
)

func Sink() *sink {
	return &sink{
		logger:     DefaultLogger,
		signer:     internalAuth.DefaultSigner,
		eventbus:   eventbus.Service(),
		isMonolith: true,
	}
}

func (svc sink) SignURL(surp SinkRequestUrlParams) (signedURL *url.URL, err error) {
	var (
		params []byte
	)

	params, err = json.Marshal(surp)
	if err != nil {
		return
	}

	surp.Method = strings.ToUpper(surp.Method)

	v := url.Values{}

	v.Set(SinkSignUrlParamName, svc.signer.Sign(0, params)+SinkSignUrlParamDelimiter+base64.StdEncoding.EncodeToString(params))

	signedURL = &url.URL{RawQuery: v.Encode(), Path: svc.GetPath()}

	return
}

func (svc sink) GetPath() string {
	path := ""

	if svc.isMonolith {
		path = "/system"
	}

	return path + "/sink"
}

// ProcessRequest handles sink request validation and processing
func (svc sink) ProcessRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	param := r.URL.Query().Get(SinkSignUrlParamName)
	if len(param) == 0 {
		http.Error(w, "missing sink signature parameter", http.StatusBadRequest)
		return
	}

	split := strings.SplitN(param, SinkSignUrlParamDelimiter, 2)
	if len(split) < 2 {
		http.Error(w, "invalid sink signature parameter", http.StatusUnauthorized)
		return
	}

	params, err := base64.StdEncoding.DecodeString(split[1])
	if err != nil {
		http.Error(w, "bad encoding of sink parameters", http.StatusBadRequest)
		return
	}

	if !svc.signer.Verify(split[0], 0, params) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	srup := &SinkRequestUrlParams{}
	if err := json.Unmarshal(params, srup); err != nil {
		// Impossible scenario :)
		// How can we have verified signature of an invalid JSON ?!
		http.Error(w, "invalid sink request url params", http.StatusInternalServerError)
		return
	}

	if srup.Method != "" && srup.Method != r.Method {
		http.Error(w, "invalid method", http.StatusUnauthorized)
		return
	}

	contentType := strings.ToLower(r.Header.Get("content-type"))
	if i := strings.Index(contentType, ";"); i > 0 {
		contentType = contentType[0 : i-1]
	}

	if srup.ContentType != "" {
		if strings.ToLower(srup.ContentType) != contentType {
			http.Error(w, "invalid content-type", http.StatusUnauthorized)
			return
		}
	}

	if srup.Expires != nil && srup.Expires.Before(time.Now()) {
		http.Error(w, "signature expired", http.StatusGone)
		return
	}

	var body io.Reader
	if srup.MaxBodySize > 0 {
		// See if there is content length param and reject it right away
		if r.ContentLength > srup.MaxBodySize {
			http.Error(w, "content length exceeds max size limit", http.StatusRequestEntityTooLarge)
		}

		// Utilize body only when max-body-size limit is set
		body = http.MaxBytesReader(w, r.Body, srup.MaxBodySize)
	} else {
		body = http.MaxBytesReader(w, r.Body, 32<<10) // 32k limit
	}

	if err := svc.process(contentType, w, r, body); err != nil {
		http.Error(w, "sink request process error", http.StatusInternalServerError)
		return
	}
}

// Processes sink request, casts it and forwards it to processor (depending on content type)
//
// Main reason for content-type & body to be passed separately (and not extracted from r param) is
// that:
// a) content type might be forced via sink params
// This is useful to enforce mail processing
// b) Max-body-size check might be limited via sink params
// and io.Reader that is passed is limited w/ io.LimitReader
//
func (svc *sink) process(contentType string, w http.ResponseWriter, r *http.Request, body io.Reader) (err error) {
	ctx := r.Context()

	switch strings.ToLower(contentType) {
	case SinkContentTypeMail, "rfc822", "email", "mail":
		// this is handled by dedicated event that parses raw payload from HTTP request
		// as rfc882 message.
		var msg *types.MailMessage
		msg, err = types.NewMailMessage(body)
		if err != nil {
			return
		}

		return svc.eventbus.WaitFor(ctx, event.MailOnReceive(msg))

	default:
		var (
			sr *types.SinkRequest

			// Predefine default response
			rsp = &types.SinkResponse{
				Status: http.StatusOK,
			}
		)

		// Sanitize URL by removing sink sign url param
		sanitizedURL := r.URL
		sanitizedQuery := r.URL.Query()
		sanitizedQuery.Del(SinkSignUrlParamName)
		sanitizedURL.RawQuery = sanitizedQuery.Encode()
		if strings.HasPrefix(sanitizedURL.Path, svc.GetPath()) {
			sanitizedURL.Path = sanitizedURL.Path[len(svc.GetPath()):]
		}

		r.URL = sanitizedURL
		r.RequestURI = sanitizedURL.String()

		sr, err = types.NewSinkRequest(r, body)
		if err != nil {
			svc.log(ctx).Error("could create sink request event", zap.Error(err))
			return
		}

		ev := event.SinkOnRequest(rsp, sr)
		err = svc.eventbus.WaitFor(ctx, ev)
		if err != nil {
			svc.log(ctx).Error("could not process event", zap.Error(err))
			return
		}

		// Now write everything we've received from the script
		//if err = rsp.Header.Write(w); err != nil {
		//	return
		//}
		for k, vv := range rsp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rsp.Status)

		var output []byte
		if bb, ok := rsp.Body.([]byte); ok {
			// Ok, handled
			output = bb
		} else if s, ok := rsp.Body.(string); ok {
			output = []byte(s)
		}

		if _, err = w.Write(output); err != nil {
			return
		}
	}

	return
}

func (svc sink) log(ctx context.Context, fields ...zapcore.Field) *zap.Logger {
	return logger.AddRequestID(ctx, svc.logger).With(fields...)
}
