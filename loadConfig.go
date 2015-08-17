package main

import (
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"os"
)

func loadConfig(filenamePath *string, filename *string) {
	log := logging.MustGetLogger("log")

	viper.SetConfigName(*filename)
	viper.AddConfigPath(*filenamePath)

	if err := viper.ReadInConfig(); err != nil {
		log.Critical("Unable to load config file:", err)
		os.Exit(1)
	}

	switch viper.GetString("logtype") {
	case "critical":
		logging.SetLevel(0, "")
		log.Debug("\"critical\" is selected")
	case "error":
		logging.SetLevel(1, "")
		log.Debug("\"error\" is selected")
	case "warning":
		logging.SetLevel(2, "")
		log.Debug("\"warning\" is selected")
	case "notice":
		logging.SetLevel(3, "")
		log.Debug("\"notice\" is selected")
	case "info":
		logging.SetLevel(4, "")
		log.Debug("\"info\" is selected")
	case "debug":
		logging.SetLevel(5, "")
		log.Debug("\"debug\" is selected")
	default:
		logging.SetLevel(2, "")
		log.Debug("\"default\" is selected (warning)")
	}

	log.Debug("loadConfig func:")
	log.Debug("  path: %s", *filenamePath)
	log.Debug("  filename: %s", *filename)
	log.Debug("  logtype in file config is \"%s\"", viper.GetString("logtype"))
}
