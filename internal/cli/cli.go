// Package cli wires up the secchk command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/linus1423/Securety-Checker/internal/check"
	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/report"
	"github.com/linus1423/Securety-Checker/internal/sandbox"
	"github.com/linus1423/Securety-Checker/internal/scanner"
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
	var noImages, noSecrets, live bool
	var trivyTimeout time.Duration
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

			if !noImages || !noSecrets {
				findings = append(findings, runTrivy(cmd, root, files, noImages, noSecrets, trivyTimeout)...)
				finding.Sort(findings)
			}

			if live {
				findings = append(findings, runLive(cmd, root, files, trivyTimeout)...)
				finding.Sort(findings)
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
	cmd.Flags().BoolVar(&noImages, "no-images", false, "skip scanning referenced images for vulnerabilities (needs trivy)")
	cmd.Flags().BoolVar(&noSecrets, "no-secrets", false, "skip scanning the project tree for secrets (needs trivy)")
	cmd.Flags().DurationVar(&trivyTimeout, "scan-timeout", 5*time.Minute, "timeout for each external scanner invocation")
	cmd.Flags().BoolVar(&live, "live", false, "start the Compose stack in a data-safe sandbox and check it at runtime (needs docker)")
	return cmd
}

// runLive starts each Compose file in a sandbox and collects runtime findings.
// Like the Trivy step it never aborts the scan: a missing Docker or a runtime
// error is reported to stderr and the static findings still stand.
func runLive(cmd *cobra.Command, root string, files []discovery.File, timeout time.Duration) []finding.Finding {
	runner := sandbox.Runner{}
	stderr := cmd.ErrOrStderr()
	if !runner.Available() {
		fmt.Fprintln(stderr, "note: docker compose not available; skipping --live runtime checks")
		return nil
	}
	var findings []finding.Finding
	for _, f := range files {
		if f.Kind != discovery.KindCompose {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(f.Path))
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		rf, err := runner.RunFile(ctx, path)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "note: live check skipped for %s: %v\n", f.Path, err)
			continue
		}
		findings = append(findings, rf...)
	}
	return findings
}

// runTrivy runs the Trivy adapter for image vulnerabilities and filesystem
// secrets. It never aborts the scan: a missing binary or a scanner error is
// reported to stderr and the static findings still stand.
func runTrivy(cmd *cobra.Command, root string, files []discovery.File, noImages, noSecrets bool, timeout time.Duration) []finding.Finding {
	tv := scanner.Trivy{}
	stderr := cmd.ErrOrStderr()
	if !tv.Available() {
		fmt.Fprintln(stderr, "note: trivy not found; skipping image and secret scans (install trivy to enable)")
		return nil
	}
	var findings []finding.Finding
	if !noSecrets {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		fs, err := tv.ScanFilesystemSecrets(ctx, root)
		cancel()
		if err != nil {
			fmt.Fprintln(stderr, "note: secret scan skipped:", err)
		} else {
			findings = append(findings, fs...)
		}
	}
	if !noImages {
		for _, img := range check.ReferencedImages(root, files) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			vf, err := tv.ScanImage(ctx, img)
			cancel()
			if err != nil {
				fmt.Fprintf(stderr, "note: image scan skipped for %s: %v\n", img, err)
				continue
			}
			findings = append(findings, vf...)
		}
	}
	return findings
}

func validFormat(f string) bool {
	for _, v := range report.Formats {
		if v == f {
			return true
		}
	}
	return false
}
