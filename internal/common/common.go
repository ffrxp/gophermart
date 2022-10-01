package common

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
)

const defaultRunAddress = ":8080"

type Config struct {
	RunAddress        string
	DatabaseURI       string
	AccrualSystemAddr string
}

func InitConfig() *Config {
	var conf Config

	defRunAddress, ok := os.LookupEnv("RUN_ADDRESS")
	if !ok || defRunAddress == "" {
		defRunAddress = defaultRunAddress
	}
	defDatabaseURI, ok := os.LookupEnv("DATABASE_URI")
	if !ok {
		defDatabaseURI = ""
	}
	defAccrualSystemAddr, ok := os.LookupEnv("ACCRUAL_SYSTEM_ADDRESS")
	if !ok {
		defAccrualSystemAddr = ""
	}

	flag.StringVar(&(conf.RunAddress), "a", defRunAddress, "Address and port of starting service")
	flag.StringVar(&(conf.DatabaseURI), "d", defDatabaseURI, "Database URI")
	flag.StringVar(&(conf.AccrualSystemAddr), "r", defAccrualSystemAddr, "Address of accrual system")
	flag.Parse()

	return &conf
}

func GenHashForRawPassword(pwd, salt string) []byte {
	pwdWithSalt := fmt.Sprintf("%s%s", pwd, salt)

	h := sha256.New()
	h.Write([]byte(pwdWithSalt))
	res := h.Sum(nil)
	return res
}

func IsValidByLuhnAlg(number int64) bool {
	return (number%10+checksum(number/10))%10 == 0
}
func checksum(number int64) int64 {
	var luhn int64

	for i := 0; number > 0; i++ {
		cur := number % 10

		if i%2 == 0 { // even
			cur = cur * 2
			if cur > 9 {
				cur = cur%10 + cur/10
			}
		}

		luhn += cur
		number = number / 10
	}
	return luhn % 10
}
