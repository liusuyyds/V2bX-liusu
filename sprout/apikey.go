package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/qingsu/atlas/base/secret"
	"github.com/spf13/cobra"
)

var (
	apiKeyValue      string
	apiKeySecretFile string
)

var apiKeyCommand = cobra.Command{
	Use:          "apikey [plain-api-key]",
	Short:        "Encrypt panel API key for config storage",
	Args:         cobra.MaximumNArgs(1),
	RunE:         encryptAPIKeyHandle,
	SilenceUsage: true,
}

func init() {
	apiKeyCommand.Flags().StringVarP(&apiKeyValue, "value", "v", "", "plain panel API key")
	apiKeyCommand.Flags().StringVarP(&apiKeySecretFile, "secret-file", "s", "", "path to api key secret file")
	command.AddCommand(&apiKeyCommand)
}

func encryptAPIKeyHandle(_ *cobra.Command, args []string) error {
	value := strings.TrimSpace(apiKeyValue)
	if value == "" && len(args) > 0 {
		value = strings.TrimSpace(args[0])
	}
	if value == "" {
		fmt.Print("请输入面板对接API Key：")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read api key error: %w", err)
		}
		value = strings.TrimSpace(line)
	}
	if value == "" {
		return fmt.Errorf("api key 不能为空")
	}

	secretValue, source, err := secret.ResolveAPIKeySecret(apiKeySecretFile, true)
	if err != nil {
		return fmt.Errorf("load api key secret error: %w", err)
	}
	encrypted, err := secret.EncryptAPIKey(value, secretValue)
	if err != nil {
		return fmt.Errorf("encrypt api key error: %w", err)
	}
	if strings.HasPrefix(source, "/") {
		fmt.Fprintf(os.Stderr, "API Key 密钥文件: %s\n", source)
	}
	fmt.Println(encrypted)
	return nil
}
