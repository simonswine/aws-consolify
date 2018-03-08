package cmd

import (
	"github.com/spf13/cobra"

	"github.com/simonswine/aws-consolify/pkg/awsconsolify"
)

var consoleCmd = &cobra.Command{
	Use:     "console",
	Aliases: []string{"c"},
	Short:   "Open AWS console in the default browser",
	Run: func(cmd *cobra.Command, args []string) {
		v := awsconsolify.New()
		v.Must(v.CmdConsole(cmd, args))
	},
}

var consoleChromeCmd = &cobra.Command{
	Use:     "chrome",
	Aliases: []string{"c"},
	Short:   "Open AWS console in chrome",
	Run: func(cmd *cobra.Command, args []string) {
		v := awsconsolify.New()
		v.Must(v.CmdConsoleChrome(cmd, args))
	},
}

var consoleFirefoxCmd = &cobra.Command{
	Use:     "firefox",
	Aliases: []string{"f"},
	Short:   "Open AWS console in firefox",
	Run: func(cmd *cobra.Command, args []string) {
		v := awsconsolify.New()
		v.Must(v.CmdConsoleFirefox(cmd, args))
	},
}

var consoleURLCmd = &cobra.Command{
	Use:   "url",
	Short: "Output AWS console URL",
	Run: func(cmd *cobra.Command, args []string) {
		v := awsconsolify.New()
		v.Must(v.CmdConsoleURL(cmd, args))
	},
}

func init() {
	consoleCmd.AddCommand(consoleChromeCmd)
	consoleCmd.AddCommand(consoleFirefoxCmd)
	consoleCmd.AddCommand(consoleURLCmd)
	consoleCmd.PersistentFlags().String(awsconsolify.FlagRegion, "us-east-1", "Region for AWS Console")
	consoleChromeCmd.PersistentFlags().Bool(awsconsolify.FlagSeperateProfile, true, "Run browser session in a separate profile")
	RootCmd.AddCommand(consoleCmd)
}
