// Command gh-lease issues short-lived, least-privilege GitHub installation
// access tokens for AI agents and automation.
//
// See README.md for the security model and policy precedence.
package main

import (
	"fmt"
	"os"

	"github.com/aconal-com/gh-lease/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gh-lease:", err)
		os.Exit(cli.ExitCode(err))
	}
}
