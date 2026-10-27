package mailer

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/mail"
	"strings"
	texttemplate "text/template"
	"unicode"

	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// RenderedEmail holds the sanitized recipient, subject, plain-text body, and HTML body.
type RenderedEmail struct {
	Recipient string
	Subject   string
	TextBody  string
	HTMLBody  string
}

type templateSpec struct {
	subject      func(data map[string]string) string
	requiredKeys []string
	textTmpl     *texttemplate.Template
	htmlTmpl     *htmltemplate.Template
}

// Engine maps email.TemplateType values to embedded templates and sanitizes injected data.
type Engine struct {
	specs map[email.TemplateType]templateSpec
}

// NewEngine parses and validates all embedded HTML and plain-text templates.
func NewEngine() (*Engine, error) {
	defs := []struct {
		kind         email.TemplateType
		txtFile      string
		htmlFile     string
		requiredKeys []string
		subject      func(map[string]string) string
	}{
		{
			kind:         email.TemplateVerifyEmail,
			txtFile:      "templates/verify_email.txt.tmpl",
			htmlFile:     "templates/verify_email.html.tmpl",
			requiredKeys: []string{"token"},
			subject: func(map[string]string) string {
				return "Verify your kr0n email address"
			},
		},
		{
			kind:         email.TemplatePasswordReset,
			txtFile:      "templates/password_reset.txt.tmpl",
			htmlFile:     "templates/password_reset.html.tmpl",
			requiredKeys: []string{"token"},
			subject: func(map[string]string) string {
				return "Reset your kr0n password"
			},
		},
		{
			kind:         email.TemplateOrgInvite,
			txtFile:      "templates/org_invite.txt.tmpl",
			htmlFile:     "templates/org_invite.html.tmpl",
			requiredKeys: []string{"org_name", "role_id", "token"},
			subject: func(d map[string]string) string {
				return fmt.Sprintf("Invitation to join %s on kr0n", d["org_name"])
			},
		},
	}

	specs := make(map[email.TemplateType]templateSpec, len(defs))
	for _, d := range defs {
		txtRaw, err := templateFS.ReadFile(d.txtFile)
		if err != nil {
			return nil, fmt.Errorf("read text template %s: %w", d.txtFile, err)
		}
		txtT, err := texttemplate.New(string(d.kind) + ".txt").Option("missingkey=error").Parse(string(txtRaw))
		if err != nil {
			return nil, fmt.Errorf("parse text template %s: %w", d.txtFile, err)
		}

		htmlRaw, err := templateFS.ReadFile(d.htmlFile)
		if err != nil {
			return nil, fmt.Errorf("read html template %s: %w", d.htmlFile, err)
		}
		htmlT, err := htmltemplate.New(string(d.kind) + ".html").Option("missingkey=error").Parse(string(htmlRaw))
		if err != nil {
			return nil, fmt.Errorf("parse html template %s: %w", d.htmlFile, err)
		}

		specs[d.kind] = templateSpec{
			subject:      d.subject,
			requiredKeys: d.requiredKeys,
			textTmpl:     txtT,
			htmlTmpl:     htmlT,
		}
	}

	return &Engine{specs: specs}, nil
}

// SanitizeAndRender validates the recipient, sanitizes all template variables, and renders
// both the plain-text and HTML email bodies for the given job.
func (e *Engine) SanitizeAndRender(job email.JobMessage) (*RenderedEmail, error) {
	spec, ok := e.specs[job.Type]
	if !ok {
		return nil, fmt.Errorf("mailer: unknown template type %q", job.Type)
	}

	recipient, err := sanitizeRecipient(job.Recipient)
	if err != nil {
		return nil, err
	}

	sanitizedData := make(map[string]string, len(job.Data))
	for k, v := range job.Data {
		cleanKey := sanitizeString(k)
		cleanVal := sanitizeString(v)
		if cleanKey != "" {
			sanitizedData[cleanKey] = cleanVal
		}
	}

	for _, reqKey := range spec.requiredKeys {
		if strings.TrimSpace(sanitizedData[reqKey]) == "" {
			return nil, fmt.Errorf("mailer: missing required template field %q for %s", reqKey, job.Type)
		}
	}

	subject := sanitizeString(spec.subject(sanitizedData))
	if subject == "" {
		return nil, errors.New("mailer: rendered subject is empty")
	}

	var txtBuf bytes.Buffer
	if err := spec.textTmpl.Execute(&txtBuf, sanitizedData); err != nil {
		return nil, fmt.Errorf("mailer: execute text template %s: %w", job.Type, err)
	}

	var htmlBuf bytes.Buffer
	if err := spec.htmlTmpl.Execute(&htmlBuf, sanitizedData); err != nil {
		return nil, fmt.Errorf("mailer: execute html template %s: %w", job.Type, err)
	}

	return &RenderedEmail{
		Recipient: recipient,
		Subject:   subject,
		TextBody:  txtBuf.String(),
		HTMLBody:  htmlBuf.String(),
	}, nil
}

func sanitizeRecipient(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("mailer: recipient email is required")
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", errors.New("mailer: recipient contains forbidden control characters")
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil || addr.Address == "" {
		return "", fmt.Errorf("mailer: invalid recipient email %q", raw)
	}
	return strings.ToLower(addr.Address), nil
}

// sanitizeString strips CR, LF, NUL, and non-printable ASCII/Unicode control characters.
func sanitizeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == 0 || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
