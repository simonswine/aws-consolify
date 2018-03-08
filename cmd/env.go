package cmd

import (
	"github.com/spf13/cobra"

	"github.com/simonswine/aws-consolify/pkg/awsconsolify"
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:     "env",
	Aliases: []string{"e"},
	Short:   "Output AWS credentials to be used by eval as environment variables",
	Run: func(cmd *cobra.Command, args []string) {
		v := awsconsolify.New()
		v.Must(v.CmdEnv(cmd, args))
	},
}

func init() {
	RootCmd.AddCommand(envCmd)
	envCmd.Flags().Bool(awsconsolify.FlagExportVars, true, "Should variables be exported?")
}
