package mailer

import (
	"strings"
	"testing"

	"github.com/skxm03/kr0n-backend/control-plane/internal/email"
)

func TestEngine_SanitizeAndRender_AllTemplates(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		job         email.JobMessage
		wantSubject string
		wantInText  string
		wantInHTML  string
	}{
		{
			name: "verify_email renders both plain-text and HTML",
			job: email.JobMessage{
				ID:        "job-1",
				Type:      email.TemplateVerifyEmail,
				Recipient: "Alice@Example.com",
				Data:      map[string]string{"token": "verif-tok-123"},
			},
			wantSubject: "Verify your kr0n email address",
			wantInText:  "verif-tok-123",
			wantInHTML:  ">verif-tok-123</code>",
		},
		{
			name: "password_reset renders both plain-text and HTML",
			job: email.JobMessage{
				ID:        "job-2",
				Type:      email.TemplatePasswordReset,
				Recipient: "bob@example.com",
				Data:      map[string]string{"token": "reset-tok-456"},
			},
			wantSubject: "Reset your kr0n password",
			wantInText:  "reset-tok-456",
			wantInHTML:  ">reset-tok-456</code>",
		},
		{
			name: "org_invite renders both plain-text and HTML and escapes HTML in org_name",
			job: email.JobMessage{
				ID:        "job-3",
				Type:      email.TemplateOrgInvite,
				Recipient: "carol@example.com",
				Data: map[string]string{
					"org_name": "Acme <script>alert(1)</script>\r\nBcc: attacker@evil.com",
					"role_id":  "admin",
					"token":    "invite-tok-789",
				},
			},
			wantSubject: "Invitation to join Acme <script>alert(1)</script>Bcc: attacker@evil.com on kr0n",
			wantInText:  "invite-tok-789",
			wantInHTML:  "&lt;script&gt;alert(1)&lt;/script&gt;",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := engine.SanitizeAndRender(tc.job)
			if err != nil {
				t.Fatalf("SanitizeAndRender() unexpected error: %v", err)
			}
			if res.Recipient != strings.ToLower(tc.job.Recipient) {
				t.Errorf("Recipient = %q, want %q", res.Recipient, strings.ToLower(tc.job.Recipient))
			}
			if strings.ContainsAny(res.Subject, "\r\n") {
				t.Errorf("Subject contains CR/LF characters: %q", res.Subject)
			}
			if res.Subject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", res.Subject, tc.wantSubject)
			}
			if !strings.Contains(res.TextBody, tc.wantInText) {
				t.Errorf("TextBody missing %q:\n%s", tc.wantInText, res.TextBody)
			}
			if !strings.Contains(res.HTMLBody, tc.wantInHTML) {
				t.Errorf("HTMLBody missing %q:\n%s", tc.wantInHTML, res.HTMLBody)
			}
			if strings.Contains(res.HTMLBody, "<script>") {
				t.Errorf("HTMLBody contains unescaped <script> tag:\n%s", res.HTMLBody)
			}
		})
	}
}

func TestEngine_SanitizeAndRender_ValidationErrors(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() unexpected error: %v", err)
	}

	cases := []struct {
		name string
		job  email.JobMessage
	}{
		{
			name: "unknown template type",
			job: email.JobMessage{
				Type:      "non_existent",
				Recipient: "user@example.com",
				Data:      map[string]string{"token": "123"},
			},
		},
		{
			name: "invalid recipient email",
			job: email.JobMessage{
				Type:      email.TemplateVerifyEmail,
				Recipient: "not-an-email",
				Data:      map[string]string{"token": "123"},
			},
		},
		{
			name: "recipient CRLF injection",
			job: email.JobMessage{
				Type:      email.TemplateVerifyEmail,
				Recipient: "user@example.com\r\nBcc: victim@example.com",
				Data:      map[string]string{"token": "123"},
			},
		},
		{
			name: "missing required template variable",
			job: email.JobMessage{
				Type:      email.TemplateOrgInvite,
				Recipient: "user@example.com",
				Data:      map[string]string{"org_name": "Acme"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := engine.SanitizeAndRender(tc.job); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
