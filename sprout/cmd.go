package cmd

import (
	log "github.com/sirupsen/logrus"

	_ "github.com/qingsu/atlas/field/imports"
	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "qingsu",
}

func Run() {
	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}
