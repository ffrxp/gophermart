package main

import (
	"github.com/ffrxp/gophermart/internal/app"
	"github.com/ffrxp/gophermart/internal/common"
	"github.com/ffrxp/gophermart/internal/handlers"
	"github.com/ffrxp/gophermart/internal/storage"
	"github.com/rs/zerolog/log"
	"net/http"
)

func main() {
	log.Info().Msg("Start gophermart")
	config := common.InitConfig()
	if config.DatabaseURI == "" {
		log.Panic().Msg("Database URI is empty.")
		//panic("Database URI is empty. Please fill it.")
	}
	appStorage, err := storage.NewDatabaseStorage(config.DatabaseURI)
	if err == nil {
		defer appStorage.Close()
		ga := app.GophermartApp{Storage: appStorage,
			DatabaseURI:       config.DatabaseURI,
			AccrualSystemAddr: config.AccrualSystemAddr}
		log.Info().Msgf("Start server. Address:'%s'|Database URI:'%s'|Accrual address:'%s'",
			config.RunAddress, config.DatabaseURI, config.AccrualSystemAddr)
		log.Panic().Msg(http.ListenAndServe(config.RunAddress, handlers.NewRouter(&ga)).Error())
	}
}
