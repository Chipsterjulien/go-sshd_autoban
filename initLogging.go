package main

import (
	"github.com/op/go-logging"
	"os"
)

func initLogging(logFilename *string) *os.File {
	log := logging.MustGetLogger("log")
	logging.MustGetLogger("log")
	format1 := logging.MustStringFormatter("%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}")
	backend1 := logging.NewLogBackend(os.Stderr, "", 0)
	backend1Formatter := logging.NewBackendFormatter(backend1, format1)
	logging.SetBackend(backend1Formatter)

	fd, err := os.OpenFile(*logFilename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Critical("Impossible to open \""+*logFilename+"\":", err)
	}
	format2 := logging.MustStringFormatter("%{shortfunc} %{message}")
	backend2 := logging.NewLogBackend(fd, "", 0)
	backend2Formatter := logging.NewBackendFormatter(backend2, format2)
	logging.SetBackend(backend1Formatter, backend2Formatter)

	return fd
}
