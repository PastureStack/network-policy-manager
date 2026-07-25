package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PastureStack/network-policy-manager/internal/enforcement"
	"github.com/PastureStack/network-policy-manager/internal/policy"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return runServe(args[1:], stdout, stderr)
		case "cleanup":
			return runCleanup(args[1:], stdout, stderr)
		}
	}
	return runAudit(args, stdin, stdout, stderr)
}

func runAudit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("network-policy-manager", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "read a policy snapshot from this JSON file instead of standard input")
	showVersion := flags.Bool("version", false, "print the build version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	input := stdin
	var file *os.File
	if *filePath != "" {
		var err error
		file, err = os.Open(*filePath)
		if err != nil {
			fmt.Fprintln(stderr, "unable to open input file")
			return 1
		}
		defer file.Close()
		input = file
	}
	config, err := policy.Decode(input)
	if err != nil {
		fmt.Fprintf(stderr, "invalid policy document: %v\n", err)
		return 1
	}
	plan, err := policy.BuildPlan(config)
	if err != nil {
		fmt.Fprintf(stderr, "invalid policy snapshot: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		fmt.Fprintln(stderr, "unable to encode plan")
		return 1
	}
	return 0
}

func runServe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("network-policy-manager serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	metadataURL := flags.String("metadata-url", "", "metadata API base URL")
	pollInterval := flags.Duration("poll-interval", 20*time.Second, "metadata reconciliation interval")
	failOpenAfter := flags.Duration("fail-open-after", 10*time.Minute, "maximum stale interval before removing enforcement")
	healthListen := flags.String("health-listen", "127.0.0.1:8092", "health endpoint listen address")
	nftBinary := flags.String("nft-binary", "nft", "nft executable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}

	listener, err := net.Listen("tcp", *healthListen)
	if err != nil {
		fmt.Fprintln(stderr, "unable to start health endpoint")
		return 1
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(stderr, "network-policy-manager: ", log.LstdFlags|log.LUTC)
	manager := &enforcement.Manager{
		Source:        enforcement.NewMetadataClient(*metadataURL),
		Backend:       enforcement.NFTBackend{Binary: *nftBinary},
		PollInterval:  *pollInterval,
		FailOpenAfter: *failOpenAfter,
		Version:       version,
		Logger:        logger,
	}
	server := &http.Server{
		Handler:           manager.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	serverError := make(chan error, 1)
	go func() {
		serverError <- server.Serve(listener)
	}()
	managerError := make(chan error, 1)
	go func() {
		managerError <- manager.Run(ctx)
	}()

	select {
	case err := <-serverError:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(stderr, "health endpoint stopped unexpectedly")
			return 1
		}
	case err := <-managerError:
		if err != nil {
			fmt.Fprintln(stderr, "policy manager stopped unexpectedly")
			return 1
		}
	case <-ctx.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
	fmt.Fprintln(stdout, "network policy manager stopped; host rules were preserved")
	return 0
}

func runCleanup(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("network-policy-manager cleanup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	confirmed := flags.Bool("yes", false, "confirm removal of the exact owned firewall table")
	nftBinary := flags.String("nft-binary", "nft", "nft executable")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if !*confirmed {
		fmt.Fprintln(stderr, "cleanup requires --yes")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := (enforcement.NFTBackend{Binary: *nftBinary}).Cleanup(ctx); err != nil {
		fmt.Fprintln(stderr, "unable to remove owned firewall state")
		return 1
	}
	fmt.Fprintln(stdout, "removed the exact owned firewall table")
	return 0
}
