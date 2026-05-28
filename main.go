package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ayitas/mcp-nvd-go/nvd"
	"github.com/ayitas/mcp-nvd-go/tools"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nvd-mcp-server:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "nvd-vulnerabilities",
		Version: "1.0.0",
	}, nil)

	tools.Register(server, nvd.NewClientFromEnv())

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
