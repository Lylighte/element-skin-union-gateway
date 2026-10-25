package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Lylighte/element-skin-union-gateway/internal/adapter/elementskin"
	"github.com/Lylighte/element-skin-union-gateway/internal/config"
	"github.com/Lylighte/element-skin-union-gateway/internal/httpapi"
	"github.com/Lylighte/element-skin-union-gateway/internal/netutil"
	"github.com/Lylighte/element-skin-union-gateway/internal/service"
	"github.com/Lylighte/element-skin-union-gateway/internal/store"
	"github.com/Lylighte/element-skin-union-gateway/internal/union"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	if command == "version" {
		fmt.Fprintln(out, service.Version)
		return nil
	}
	if command == "generate-secret" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		fmt.Fprintln(out, hex.EncodeToString(b))
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", "config.yaml", "configuration file")
	target := flags.String("url", "", "healthcheck URL; defaults to configured local health endpoint")
	action := flags.String("action", "status", "admin action: status, sync, refresh-directory, refresh-key, diagnose")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if command == "healthcheck" {
		if *target == "" {
			c, e := config.Load(*path)
			if e != nil {
				return e
			}
			host, port, _ := net.SplitHostPort(c.Listen)
			if host == "" || host == "0.0.0.0" || host == "::" {
				host = "127.0.0.1"
			}
			*target = "http://" + net.JoinHostPort(host, port) + c.RootPath() + "/health/live"
		}
		res, err := netutil.Do(ctx, netutil.Client(3*time.Second), "GET", *target, nil, http.Header{})
		if err != nil {
			return err
		}
		if res.Status != 200 {
			return fmt.Errorf("healthcheck_failed: %d", res.Status)
		}
		return nil
	}
	if command != "serve" && command != "check-config" && command != "admin" {
		return fmt.Errorf("unknown command")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if command == "check-config" {
		fmt.Fprintln(out, "configuration valid")
		return nil
	}
	if command == "admin" {
		switch *action {
		case "status", "sync", "refresh-directory", "refresh-key", "diagnose":
		default:
			return fmt.Errorf("unknown admin action")
		}
		host, port, _ := net.SplitHostPort(c.Listen)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		method := "POST"
		if *action == "status" {
			method = "GET"
		}
		h := http.Header{"Authorization": {"Bearer " + c.AdminToken}}
		res, e := netutil.Do(ctx, netutil.Client(110*time.Second), method, "http://"+net.JoinHostPort(host, port)+c.RootPath()+"/admin/"+*action, nil, h)
		if e != nil {
			return e
		}
		_, _ = out.Write(res.Body)
		if res.Status != 200 {
			return fmt.Errorf("admin_action_failed: %d", res.Status)
		}
		return nil
	}
	log := slog.New(slog.NewJSONHandler(errOut, nil))
	st, err := store.Open(c.StatePath, c.SecretDir)
	if err != nil {
		return fmt.Errorf("state_open_failed")
	}
	defer st.Close()
	client := netutil.Client(c.Timeout())
	skin := elementskin.New(c.ElementSkinURL, c.ClientID, c.ClientSecret, client)
	s, err := service.New(ctx, c, st, skin, union.New(union.Root, client), log)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.Listen, Handler: httpapi.New(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("listen_failed")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); s.Run(workerCtx) }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Info("gateway_started", "version", service.Version, "listen", c.Listen, "public_root", c.PublicRoot)
	select {
	case err = <-done:
		cancel()
		<-workerDone
		if err != http.ErrServerClosed {
			return fmt.Errorf("server_failed")
		}
	case <-ctx.Done():
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err = server.Shutdown(shutdownCtx); err != nil {
			server.Close()
		}
		<-workerDone
	}
	return nil
}
