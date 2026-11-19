package mailer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSMTPServer struct {
	addr        string
	listener    net.Listener
	mu          sync.Mutex
	from        string
	to          []string
	data        string
	quit        bool
	authMethods []string
	user        string
	password    string
	dialCount   int
}

func startMockSMTPServer(t *testing.T, authUser, authPass string) *mockSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockSMTPServer{
		addr:     ln.Addr().String(),
		listener: ln,
		user:     authUser,
		password: authPass,
	}
	if authUser != "" {
		s.authMethods = []string{"PLAIN"}
	}
	go s.serve()
	return s
}

func (s *mockSMTPServer) close() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *mockSMTPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.dialCount++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *mockSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}

	writeLine("220 mock-smtp.kr0n.dev ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "EHLO", "HELO":
			if len(s.authMethods) > 0 {
				writeLine("250-mock-smtp.kr0n.dev")
				writeLine("250 AUTH PLAIN")
			} else {
				writeLine("250 mock-smtp.kr0n.dev")
			}
		case "AUTH":
			writeLine("235 2.7.0 Authentication successful")
		case "MAIL":
			s.mu.Lock()
			s.from = parts[1]
			s.mu.Unlock()
			writeLine("250 2.1.0 Ok")
		case "RCPT":
			s.mu.Lock()
			s.to = append(s.to, parts[1])
			s.mu.Unlock()
			writeLine("250 2.1.5 Ok")
		case "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dataLine == ".\r\n" || dataLine == ".\n" {
					break
				}
				body.WriteString(dataLine)
			}
			s.mu.Lock()
			s.data = body.String()
			s.mu.Unlock()
			writeLine("250 2.0.0 Ok: queued")
		case "QUIT":
			s.mu.Lock()
			s.quit = true
			s.mu.Unlock()
			writeLine("221 2.0.0 Bye")
			return
		default:
			writeLine("500 5.5.2 Command unrecognized")
		}
	}
}

func TestSMTPSender(t *testing.T) {
	mock := startMockSMTPServer(t, "user1", "pass1")
	defer mock.close()

	sender := NewSMTPSender(SMTPConfig{
		Addr:     mock.addr,
		From:     "noreply@kr0n.dev",
		Username: "user1",
		Password: "pass1",
		Timeout:  2 * time.Second,
	})

	ctx := context.Background()
	err := sender.DispatchMIME(ctx, "user@example.com", "Test Subject", "Hello plain text", "<p>Hello HTML</p>")
	if err != nil {
		t.Fatalf("DispatchMIME failed: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if !strings.Contains(mock.from, "noreply@kr0n.dev") {
		t.Errorf("expected from noreply@kr0n.dev, got %q", mock.from)
	}
	if len(mock.to) != 1 || !strings.Contains(mock.to[0], "user@example.com") {
		t.Errorf("expected recipient user@example.com, got %v", mock.to)
	}
	if !strings.Contains(mock.data, "Subject: Test Subject") {
		t.Errorf("expected subject in data, got %q", mock.data)
	}
	if !strings.Contains(mock.data, "Hello plain text") || !strings.Contains(mock.data, "<p>Hello HTML</p>") {
		t.Errorf("expected text and HTML in multipart body, got %q", mock.data)
	}
	if !mock.quit {
		t.Errorf("expected QUIT command sent")
	}
}

func TestSMTPSender_HeaderInjection(t *testing.T) {
	sender := NewSMTPSender(SMTPConfig{
		Addr: "localhost:1025",
		From: "noreply@kr0n.dev\r\nBcc: evil@attacker.com",
	})

	err := sender.DispatchMIME(context.Background(), "good@kr0n.dev", "Subject", "Body", "")
	if err == nil || !strings.Contains(err.Error(), "header injection") {
		t.Fatalf("expected header injection rejection, got %v", err)
	}
}

func TestSMTPSender_NetworkTimeoutsErrorsAndNoLeaks(t *testing.T) {
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	refusedSender := NewSMTPSender(SMTPConfig{Addr: closedAddr, From: "noreply@kr0n.dev", Timeout: 200 * time.Millisecond})
	err = refusedSender.DispatchMIME(context.Background(), "user@kr0n.dev", "Test", "Body", "")
	if err == nil {
		t.Fatalf("expected dial failure on closed port, got nil")
	}

	// Dial-stall server: accepts TCP but never writes greeting banner
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer stallLn.Close()

	go func() {
		for {
			conn, err := stallLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	stallSender := NewSMTPSender(SMTPConfig{Addr: stallLn.Addr().String(), From: "noreply@kr0n.dev", Timeout: 120 * time.Millisecond})
	start := time.Now()
	err = stallSender.DispatchMIME(context.Background(), "user@kr0n.dev", "Test", "Body", "")
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error on stalling SMTP greeting, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
	if duration < 100*time.Millisecond || duration > 1500*time.Millisecond {
		t.Fatalf("expected timeout to trigger around 120ms, took %v", duration)
	}
}
