package service

import (
	"bytes"
	"context"
	"github.com/cortezaproject/corteza-server/pkg/settings"
	"image"
	"image/gif"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/edwvee/exiffix"
	"github.com/pkg/errors"
	"github.com/titpetric/factory"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	intAuth "github.com/cortezaproject/corteza-server/pkg/auth"
	"github.com/cortezaproject/corteza-server/pkg/logger"
	"github.com/cortezaproject/corteza-server/pkg/store"
	"github.com/cortezaproject/corteza-server/system/repository"
	"github.com/cortezaproject/corteza-server/system/types"
)

const (
	attachmentPreviewMaxWidth  = 320
	attachmentPreviewMaxHeight = 180
)

type (
	attachment struct {
		db     *factory.DB
		ctx    context.Context
		logger *zap.Logger

		store store.Store

		ac attachmentAccessController

		settingsSvc settings.Service

		attachment repository.AttachmentRepository
	}

	attachmentAccessController interface {
		CanManageSettings(context.Context) bool
	}

	AttachmentService interface {
		With(ctx context.Context) AttachmentService

		FindByID(attachmentID uint64) (*types.Attachment, error)
		Find(filter types.AttachmentFilter) (types.AttachmentSet, types.AttachmentFilter, error)
		CreateSettingsAttachment(name string, size int64, fh io.ReadSeeker, labels map[string]string) (*types.Attachment, error)
		OpenOriginal(att *types.Attachment) (io.ReadSeeker, error)
		OpenPreview(att *types.Attachment) (io.ReadSeeker, error)
		DeleteByID(attachmentID uint64) error
	}
)

func Attachment(store store.Store) AttachmentService {
	return (&attachment{
		logger: DefaultLogger.Named("attachment"),
		store:  store,
		ac:     DefaultAccessControl,

		settingsSvc: DefaultSettings,
	}).With(context.Background())
}

func (svc attachment) With(ctx context.Context) AttachmentService {
	db := repository.DB(ctx)
	return &attachment{
		db:     db,
		ctx:    ctx,
		logger: svc.logger,

		ac: svc.ac,

		settingsSvc: svc.settingsSvc,

		store: svc.store,

		attachment: repository.Attachment(ctx, db),
	}
}

// log() returns zap's logger with requestID from current context and fields.
func (svc attachment) log(fields ...zapcore.Field) *zap.Logger {
	return logger.AddRequestID(svc.ctx, svc.logger).With(fields...)
}

func (svc attachment) FindByID(attachmentID uint64) (*types.Attachment, error) {
	return svc.attachment.FindByID(attachmentID)
}

func (svc attachment) DeleteByID(attachmentID uint64) error {
	return svc.attachment.DeleteByID(attachmentID)
}

func (svc attachment) Find(filter types.AttachmentFilter) (types.AttachmentSet, types.AttachmentFilter, error) {
	return svc.attachment.Find(filter)
}

func (svc attachment) OpenOriginal(att *types.Attachment) (io.ReadSeeker, error) {
	if len(att.Url) == 0 {
		return nil, nil
	}

	return svc.store.Open(att.Url)
}

func (svc attachment) OpenPreview(att *types.Attachment) (io.ReadSeeker, error) {
	if len(att.PreviewUrl) == 0 {
		return nil, nil
	}

	return svc.store.Open(att.PreviewUrl)
}

func (svc attachment) CreateSettingsAttachment(name string, size int64, fh io.ReadSeeker, labels map[string]string) (att *types.Attachment, err error) {
	var (
		currentUserID uint64 = intAuth.GetIdentityFromContext(svc.ctx).Identity()
	)

	if !svc.ac.CanManageSettings(svc.ctx) {
		return nil, ErrNoUpdatePermissions.withStack()
	}

	att = &types.Attachment{
		ID:      factory.Sonyflake.NextID(),
		OwnerID: currentUserID,
		Name:    strings.TrimSpace(name),
		Kind:    types.AttachmentKindSettings,
	}

	if labels != nil {
		att.Meta.Labels = labels
	}

	if err = svc.create(name, size, fh, att); err != nil {
		return nil, err
	}

	return att, err
}

func (svc attachment) create(name string, size int64, fh io.ReadSeeker, att *types.Attachment) (err error) {
	if svc.store == nil {
		return errors.New("Can not create attachment: store handler not set")
	}

	log := svc.log(
		zap.String("name", att.Name),
		zap.Int64("size", att.Meta.Original.Size),
	)

	// Extract extension but make sure path.Ext is not confused by any leading/trailing dots
	att.Meta.Original.Extension = strings.Trim(path.Ext(strings.Trim(name, ".")), ".")

	att.Meta.Original.Size = size
	if att.Meta.Original.Mimetype, err = svc.extractMimetype(fh); err != nil {
		log.Error("could not extract mime-type", zap.Error(err))
		return
	}

	att.Url = svc.store.Original(att.ID, att.Meta.Original.Extension)
	log = log.With(zap.String("url", att.Url))

	if err = svc.store.Save(att.Url, fh); err != nil {
		log.Error("could not store file", zap.Error(err))
		return
	}

	// Process image: extract width, height, make preview
	err = svc.processImage(fh, att)
	if err != nil {
		log.Error("could not process image", zap.Error(err))
	}

	return svc.db.Transaction(func() (err error) {
		if att, err = svc.attachment.Create(att); err != nil {
			return
		}

		return nil
	})
}

func (svc attachment) extractMimetype(file io.ReadSeeker) (mimetype string, err error) {
	if _, err = file.Seek(0, 0); err != nil {
		return
	}

	// Make sure we rewind when we're done
	defer file.Seek(0, 0)

	// See http.DetectContentType about 512 bytes
	var buf = make([]byte, 512)
	if _, err = file.Read(buf); err != nil {
		return
	}

	return http.DetectContentType(buf), nil
}

func (svc attachment) processImage(original io.ReadSeeker, att *types.Attachment) (err error) {
	if !strings.HasPrefix(att.Meta.Original.Mimetype, "image/") {
		// Only supporting previews from images (for now)
		return
	}

	var (
		preview       image.Image
		opts          []imaging.EncodeOption
		format        imaging.Format
		previewFormat imaging.Format
		animated      bool
		f2m           = map[imaging.Format]string{
			imaging.JPEG: "image/jpeg",
			imaging.GIF:  "image/gif",
		}

		f2e = map[imaging.Format]string{
			imaging.JPEG: "jpg",
			imaging.GIF:  "gif",
		}
	)

	if _, err = original.Seek(0, 0); err != nil {
		return
	}

	if format, err = imaging.FormatFromExtension(att.Meta.Original.Extension); err != nil {
		return errors.Wrapf(err, "Could not get format from extension '%s'", att.Meta.Original.Extension)
	}

	previewFormat = format

	if imaging.JPEG == format {
		// Rotate image if needed
		// if preview, _, err = exiffix.Decode(original); err != nil {
		// 	return errors.Wrapf(err, "Could not decode EXIF from JPEG")
		// }
		preview, _, _ = exiffix.Decode(original)
	}

	if imaging.GIF == format {
		// Decode all and check loops & delay to determine if GIF is animated or not
		if cfg, err := gif.DecodeAll(original); err == nil {
			animated = cfg.LoopCount > 0 || len(cfg.Delay) > 1

			// Use first image for the preview
			preview = cfg.Image[0]
		} else {
			return errors.Wrapf(err, "Could not decode gif config")
		}

	} else {
		// Use GIF preview for GIFs and JPEG for everything else!
		previewFormat = imaging.JPEG

		// Store with a bit lower quality
		opts = append(opts, imaging.JPEGQuality(85))
	}

	// In case of JPEG we decode the image and rotate it beforehand
	// other cases are handled here
	if preview == nil {
		if preview, err = imaging.Decode(original); err != nil {
			return errors.Wrapf(err, "Could not decode original image")
		}
	}

	var width, height = preview.Bounds().Max.X, preview.Bounds().Max.Y
	att.SetOriginalImageMeta(width, height, animated)

	if width > attachmentPreviewMaxWidth && width > height {
		// Landscape does not fit
		preview = imaging.Resize(preview, attachmentPreviewMaxWidth, 0, imaging.Lanczos)
	} else if height > attachmentPreviewMaxHeight {
		// Height does not fit
		preview = imaging.Resize(preview, 0, attachmentPreviewMaxHeight, imaging.Lanczos)
	}

	// Get dimensions from the preview
	width, height = preview.Bounds().Max.X, preview.Bounds().Max.Y

	var buf = &bytes.Buffer{}
	if err = imaging.Encode(buf, preview, previewFormat, opts...); err != nil {
		return
	}

	meta := att.SetPreviewImageMeta(width, height, false)
	meta.Size = int64(buf.Len())
	meta.Mimetype = f2m[previewFormat]
	meta.Extension = f2e[previewFormat]

	// Can and how we make a preview of this attachment?
	att.PreviewUrl = svc.store.Preview(att.ID, meta.Extension)

	return svc.store.Save(att.PreviewUrl, buf)
}

var _ AttachmentService = &attachment{}
