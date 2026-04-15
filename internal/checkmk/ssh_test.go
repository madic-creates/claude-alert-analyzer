package checkmk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDialSSH_MissingKeyFile(t *testing.T) {
	cfg := Config{
		SSHKeyPath:        "/nonexistent/key",
		SSHKnownHostsPath: "/nonexistent/known_hosts",
		SSHUser:           "test",
	}
	_, err := dialSSH(cfg, "localhost")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

// startTestSSHServer starts a minimal in-process SSH server.
// handleExec is called with the command string and the open session channel;
// the handler is responsible for writing output and closing the channel.
func startTestSSHServer(t *testing.T, handleExec func(cmd string, ch ssh.Channel)) *ssh.Client {
	t.Helper()

	// Ephemeral host key
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	// Ephemeral client key
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	authorizedKey, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(authorizedKey.Marshal()) == string(key.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			return
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go serveSession(ch, requests, handleExec)
		}
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// serveSession handles one SSH session channel, dispatching exec requests to handleExec.
func serveSession(ch ssh.Channel, requests <-chan *ssh.Request, handleExec func(string, ssh.Channel)) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if len(req.Payload) < 4 {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
		cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
		cmd := string(req.Payload[4 : 4+cmdLen])
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		handleExec(cmd, ch)
		return
	}
}

// sendExitStatus sends an SSH exit-status channel request with the given code.
func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	_, _ = ch.SendRequest("exit-status", false, payload)
}

func TestRunSSHCommand_Success(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "hello output\n")
		sendExitStatus(ch, 0)
	})

	out, err := runSSHCommand(client, []string{"echo", "hello"}, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello output\n" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunSSHCommand_CommandError(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, ch ssh.Channel) {
		_, _ = io.WriteString(ch, "command not found\n")
		sendExitStatus(ch, 127)
	})

	// CombinedOutput returns an *ssh.ExitError on non-zero exit status
	_, err := runSSHCommand(client, []string{"nonexistent"}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for non-zero exit status")
	}
}

func TestRunSSHCommand_Timeout(t *testing.T) {
	client := startTestSSHServer(t, func(_ string, _ ssh.Channel) {
		// Simulate a slow command: hold the server-side channel open so
		// CombinedOutput on the client side blocks until our timeout fires.
		time.Sleep(10 * time.Second)
	})

	_, err := runSSHCommand(client, []string{"sleep", "100"}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error message, got: %v", err)
	}
}
