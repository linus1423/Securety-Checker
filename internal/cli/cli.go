// Package cli wires up the secchk command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/linus1423/Securety-Checker/internal/check"
	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/report"
)

// Version is set at build time via -ldflags "-X .../internal/cli.Version=v0.1.0".
var Version = "dev"

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// errFindings signals that the scan succeeded but found issues at or above --fail-on.
var errFindings = errors.New("findings at or above the --fail-on threshold")

// Execute runs the CLI with the given arguments and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errFindings):
		return ExitFindings
	default:
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "secchk",
		Short:         "Security checker for Docker and Docker Compose projects",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newScanCmd(), newRulesCmd(), newVersionCmd())
	return root
}

func newRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List the available checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSEVERITY\tTITLE")
			for _, r := range check.DockerfileRules {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Severity, r.Title)
			}
			for _, r := range check.ComposeRules {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Severity, r.Title)
			}
			return w.Flush()
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "secchk", Version)
			return err
		},
	}
}

func newScanCmd() *cobra.Command {
	var format, failOn string
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project directory for Dockerfile and Compose security issues",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			if !validFormat(format) {
				return fmt.Errorf("--format: unknown format %q (expected %s)", format, strings.Join(report.Formats, ", "))
			}
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return fmt.Errorf("--fail-on: %w", err)
			}
			info, err := os.Stat(root)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", root)
			}

			files, err := discovery.Walk(root)
			if err != nil {
				return err
			}
			findings, err := check.Run(root, files)
			if err != nil {
				return err
			}

			if err := report.Write(cmd.OutOrStdout(), format, report.Result{Root: root, Files: files, Findings: findings}); err != nil {
				return err
			}
			if finding.AnyAtLeast(findings, threshold) {
				return errFindings
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: "+strings.Join(report.Formats, ", "))
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit with code 1 if a finding has at least this severity (info, low, medium, high, critical)")
	return cmd
}

func validFormat(f string) bool {
	for _, v := range report.Formats {
		if v == f {
			return true
		}
	}
	return false
}
