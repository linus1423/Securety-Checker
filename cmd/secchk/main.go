// Command secchk scans Docker and Docker Compose projects for security issues.
package main

import (
	"os"

	"github.com/linus1423/Securety-Checker/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
