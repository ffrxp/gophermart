package currency

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
)

type Currency struct {
	Rubles  int
	Kopecks int
}

var ErrIncorrectValue = errors.New("currency: incorrect value")
var ErrNegativeValue = errors.New("currency: negative value")

func NewCurrency(rubles int, kopecks int) (*Currency, error) {
	if rubles < 0 || kopecks < 0 {
		return nil, ErrNegativeValue
	}
	if kopecks > 99 {
		return nil, ErrIncorrectValue
	}
	return &Currency{rubles, kopecks}, nil
}

func (currency *Currency) Add(addingCurrency *Currency) {
	currency.Rubles += addingCurrency.Rubles
	currency.Kopecks += addingCurrency.Kopecks
	if currency.Kopecks >= 100 {
		currency.Rubles += 1
		currency.Kopecks -= 100
	}
}

func (currency *Currency) Subtract(subtractingCurrency *Currency) error {
	currency.Rubles -= subtractingCurrency.Rubles
	if currency.Rubles < 0 {
		return ErrNegativeValue
	}
	currency.Kopecks -= subtractingCurrency.Kopecks
	if currency.Kopecks < 0 {
		currency.Rubles -= 1
		if currency.Rubles < 0 {
			return ErrNegativeValue
		}
		currency.Kopecks = currency.Kopecks + 100
	}
	return nil
}

func (currency *Currency) IsZero() bool {
	if currency.Rubles == 0 && currency.Kopecks == 0 {
		return true
	}
	return false
}

func (currency *Currency) ToFloat() float32 {
	var result float32
	result = float32(currency.Rubles) + (float32(currency.Kopecks) / 100)
	return result
}

func (currency Currency) Value() (driver.Value, error) {
	var result int64
	result = int64((currency.Rubles * 100) + currency.Kopecks)

	return result, nil
}

func (currency *Currency) Scan(value interface{}) error {
	if value == nil {
		newCurrency, _ := NewCurrency(0, 0)
		*currency = *newCurrency
		return nil
	}
	readVal, err := driver.Int32.ConvertValue(value)
	if err != nil {
		log.Error().Err(err).Msgf("Cannot scan currency value")
		return err
	}
	intVal, ok := readVal.(int64)
	if !ok {
		log.Error().Err(err).Msgf("Cannot scan currency value. Cannot convert value to int64")
		return err
	}
	rubles := int(intVal / 100)
	kopecks := int(intVal % 100)
	newCurrency, _ := NewCurrency(rubles, kopecks)
	*currency = *newCurrency
	return nil
}

func (currency *Currency) String() string {
	return fmt.Sprintf("%d.%d", currency.Rubles, currency.Kopecks)
}
