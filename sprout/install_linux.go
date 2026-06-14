package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/qingsu/atlas/base/exec"
	"github.com/spf13/cobra"
)

var targetVersion string

var (
	updateCommand = cobra.Command{
		Use:   "update",
		Short: "Update qingsu version",
		Run: func(_ *cobra.Command, _ []string) {
			if targetVersion == "" {
				exec.RunCommandStd("bash", "-c",
					"curl -Ls https://raw.githubusercontent.com/liusuyyds/V2bX-script/master/install.sh | bash")
				return
			}
			exec.RunCommandStd("bash", "-c",
				"curl -Ls https://raw.githubusercontent.com/liusuyyds/V2bX-script/master/install.sh | bash -s -- \"$1\"",
				"qingsu-update",
				targetVersion)
		},
		Args: cobra.NoArgs,
	}
	uninstallCommand = cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall qingsu",
		Run:   uninstallHandle,
	}
)

func init() {
	updateCommand.PersistentFlags().StringVar(&targetVersion, "version", "", "update target version")
	command.AddCommand(&updateCommand)
	command.AddCommand(&uninstallCommand)
}

func uninstallHandle(_ *cobra.Command, _ []string) {
	var yes string
	fmt.Println(Warn("确定要卸载 qingsu 吗?(Y/n)"))
	fmt.Scan(&yes)
	if strings.ToLower(yes) != "y" {
		fmt.Println("已取消卸载")
	}
	_, err := exec.RunCommandByShell("systemctl stop qingsu&&systemctl disable qingsu")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("卸载失败"))
		return
	}
	_ = os.RemoveAll("/etc/systemd/system/qingsu.service")
	_ = os.RemoveAll("/etc/qingsu/")
	_ = os.RemoveAll("/srv/qingsu/")
	_ = os.RemoveAll("/bin/qingsu")
	_, err = exec.RunCommandByShell("systemctl daemon-reload&&systemctl reset-failed")
	if err != nil {
		fmt.Println(Err("exec cmd error: ", err))
		fmt.Println(Err("卸载失败"))
		return
	}
	fmt.Println(Ok("卸载成功"))
}
