package main

import (
	"flag"
	"fmt"
	"github.com/cortezaproject/corteza-server/codegen/v2/internal"
	"github.com/cortezaproject/corteza-server/pkg/cli"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

const (
	eventsTemplateFile = "codegen/v2/auditlog/*.go.tpl"
)

type (
	// List of event/log properties that can/will be captured
	// and injected into log or message string
	defMeta struct {
		Name string
		Type string
	}

	// Event definition
	auditEventDef struct {
		// Formatted and readable audit log message
		Log string `yaml:"log"`

		// Error message
		// message can contain {variables} from meta data
		// (converts event to error)
		Error string `yaml:"error"`

		// Reference to "safe" error
		// safe error should hide any information that might cause
		// personal data leakage or expose system internals
		// (converts event to error)
		Safe string `yaml:"safe"`

		// Error severity
		// (converts event to error)
		Severity string `yaml:"severity"`
	}

	auditEvents map[string]*auditEventDef
)

const (
	defSuffix = "_auditlog.yaml"
)

var (
	// Cut off this binary
	defs = os.Args[1:]

	overwrite bool
	preview   bool

	tpl *template.Template

	placeholderMatcher = regexp.MustCompile(`{(.+?)}`)
)

func main() {
	tpl = template.New("").Funcs(map[string]interface{}{
		"camelCase": internal.CamelCase,
	})

	tpl = template.Must(tpl.ParseGlob(eventsTemplateFile))

	flag.BoolVar(&overwrite, "overwrite", false, "Overwrite all files")
	flag.BoolVar(&preview, "preview", false, "Output to stdout instead of outputPath")
	flag.Parse()

	for _, path := range defs {
		defs, err := filepath.Glob(path + "/*" + defSuffix)
		if err != nil {
			cli.HandleError(err)
		}

		for _, def := range defs {
			base := filepath.Base(def)
			procDef(def, filepath.Join(filepath.Dir(def), base[0:len(base)-len(defSuffix)]+"_auditlog.gen.go"))
		}
	}
}

func procDef(path, output string) {
	println(path, output)
	var (
		decoder *yaml.Decoder
		tplData = struct {
			Command string
			YAML    string

			Package string

			// List of imports
			// Used only by generated file and not pre-generated-user-file
			Imports []string

			Service string      `yaml:"service"`
			Target  string      `yaml:"target"`
			Meta    []*defMeta  `yaml:"meta"`
			Events  auditEvents `yaml:"events"`
		}{
			Package: "service",
			YAML:    path,
		}
	)

	if f, err := os.Open(path); err != nil {
		cli.HandleError(err)
	} else {
		decoder = yaml.NewDecoder(f)
	}

	tplData.Events = make(map[string]*auditEventDef)
	tplData.Events["generic"] = &auditEventDef{
		Log:      "server failed to complete request due to an error: {err}",
		Error:    "failed to complete request due to internal error",
		Severity: "error",
	}

	cli.HandleError(decoder.Decode(&tplData))

	// index known meta fields and sanitize types (no type => string type)
	knownMeta := map[string]bool{"err": true}
	for _, m := range tplData.Meta {
		knownMeta[m.Name] = true
		if m.Type == "" {
			m.Type = "string"
		}
	}

	// Sort events to ensure output consistenct

	for action, e := range tplData.Events {
		if !e.IsError() && e.Severity == "" {
			e.Severity = "info"
		}

		for _, match := range placeholderMatcher.FindAllStringSubmatch(e.Error, 1) {
			placeholder := match[1]
			if !knownMeta[placeholder] {
				cli.HandleError(fmt.Errorf(
					"%s: unknown placeholder %q used in %s's error", path, placeholder, action))
			}
		}

		for _, match := range placeholderMatcher.FindAllStringSubmatch(e.Log, 1) {
			placeholder := match[1]
			if !knownMeta[placeholder] {
				cli.HandleError(fmt.Errorf(
					"%s: unknown placeholder %q used in %s's log", path, placeholder, action))
			}
		}
	}

	internal.WriteTo(tpl, tplData, "auditlog.gen.go.tpl", output)
}

func (e auditEventDef) IsError() bool {
	return len(e.Error+e.Safe) > 0
}

func (e auditEventDef) SeverityConstName() string {
	switch strings.ToLower(e.Severity) {
	case "emergency":
		return "auditlog.Emergency"
	case "alert":
		return "auditlog.Alert"
	case "crit", "critical":
		return "auditlog.Critical"
	case "warn", "warning":
		return "auditlog.Warning"
	case "notice":
		return "auditlog.Notice"
	case "info", "informational":
		return "auditlog.Info"
	case "debug":
		return "auditlog.Debug"
	default:
		return "auditlog.Error"
	}
}
