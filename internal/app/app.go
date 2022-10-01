package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ffrxp/gophermart/internal/common"
	"github.com/ffrxp/gophermart/internal/currency"
	"github.com/ffrxp/gophermart/internal/storage"
	"github.com/rs/zerolog/log"
	"strconv"
	"time"
)

const salt = "some_salt"

type GophermartApp struct {
	Storage           storage.Repository
	DatabaseURI       string
	AccrualSystemAddr string
}

type BalanceData struct {
	Balance   *currency.Currency
	Withdrawn *currency.Currency
}

func (bd BalanceData) MarshalJSON() ([]byte, error) {
	type BalanceDataWithFloat struct {
		Balance   float32 `json:"current"`
		Withdrawn float32 `json:"withdrawn"`
	}
	balanceDataWithInt := &BalanceDataWithFloat{bd.Balance.ToFloat(), bd.Withdrawn.ToFloat()}
	return json.Marshal(balanceDataWithInt)
}

var ErrWrongOrderID = errors.New("app: wrong order ID")
var ErrBalanceTooLow = errors.New("app: balance too low")
var ErrAnotherUserOrder = errors.New("app: order was made by another user")
var ErrOrderWasLoaded = errors.New("app: order has been already loaded")
var ErrOrderIDIIncorrect = errors.New("app: order ID doesn't pass integrity checking")

func (gapp *GophermartApp) RegisterUser(login, password string) error {
	log.Info().Msgf("App: Registering user with login %s", login)
	pwdHash := common.GenHashForRawPassword(password, salt)
	if err := gapp.Storage.AddUser(login, pwdHash); err != nil {
		return err
	}
	return nil
}

func (gapp *GophermartApp) UserCredentialsIsValid(login, password string) (bool, error) {
	log.Info().Msgf("App: Check user credentials with login %s", login)
	expectedPwdHash, err := gapp.Storage.GetPwdHashForLogin(login)
	if err != nil {
		if errors.Is(err, storage.ErrEmptyResult) {
			return false, nil
		}
		return false, err
	}
	pwdHash := common.GenHashForRawPassword(password, salt)
	compareRet := bytes.Compare(pwdHash, expectedPwdHash)
	if compareRet != 0 {
		return false, nil
	}
	return true, nil
}

func (gapp *GophermartApp) LoadOrder(login string, orderID string) error {
	log.Info().Msgf("App: load order with ID %s for user %s", orderID, login)

	// Проверка на целостность по алгоритму Луна
	digitOrderID, err := strconv.ParseInt(orderID, 10, 0)
	if err != nil {
		return ErrOrderIDIIncorrect
	}
	if !common.IsValidByLuhnAlg(digitOrderID) {
		return ErrOrderIDIIncorrect
	}

	userUUID, err := gapp.Storage.GetUserUUID(login)
	if err != nil {
		return err
	}
	order, err := gapp.Storage.GetOrderByID(orderID)
	if err != nil {
		if errors.Is(err, storage.ErrEmptyResult) {
			accrual, _ := currency.NewCurrency(0, 0)
			order := storage.Order{ID: orderID,
				UserID:     userUUID,
				Status:     "NEW",
				Accrual:    accrual,
				UploadedAt: time.Now()}
			err = gapp.Storage.AddOrder(order)
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}

	if order.UserID != userUUID {
		return ErrAnotherUserOrder
	} else {
		return ErrOrderWasLoaded
	}
}

func (gapp *GophermartApp) ApplyAccrualSystemData(orderID string, status string, accrual *currency.Currency, userLogin string) error {
	log.Info().Msgf("App: apply accrual system data. Order ID:%s, status:%s, accrual:%d", orderID, status, accrual)
	if status == "REGISTERED" {
		return nil
	}
	err := gapp.Storage.UpdateOrder(orderID, status, accrual)
	if err != nil {
		return err
	}
	if status == "PROCESSED" {
		balance, err := gapp.Storage.GetUserBalance(userLogin)
		if err != nil {
			return err
		}
		balance.Add(accrual)
		err = gapp.Storage.SetUserBalance(userLogin, balance)
		if err != nil {
			return err
		}
	}
	return nil
}

func (gapp *GophermartApp) GetUserOrders(login string) ([]storage.Order, error) {
	log.Info().Msgf("App: Get orders for user with login %s", login)
	orders, err := gapp.Storage.GetUserOrders(login)
	if err != nil {
		if errors.Is(err, storage.ErrEmptyResult) {
			return nil, nil
		}
		return nil, err
	}
	return orders, nil
}

func (gapp *GophermartApp) GetUserBalance(login string) (BalanceData, error) {
	log.Info().Msgf("App: Get balance for user with login %s", login)
	balance, err := gapp.Storage.GetUserBalance(login)
	if err != nil {

		return BalanceData{nil, nil}, err
	}
	withdrawn, err := gapp.Storage.GetUserTotalWithdrawal(login)
	if err != nil {
		return BalanceData{nil, nil}, err
	}
	return BalanceData{balance, withdrawn}, nil
}

func (gapp *GophermartApp) GetUserWithdrawals(login string) ([]storage.Withdrawal, error) {
	log.Info().Msgf("App: Get withdrawals for user with login %s", login)
	withdrawals, err := gapp.Storage.GetUserWithdrawals(login)
	if err != nil {
		if errors.Is(err, storage.ErrEmptyResult) {
			return nil, nil
		}
		return nil, err
	}
	return withdrawals, nil
}

func (gapp *GophermartApp) DoWithdraw(login string, orderID string, sum *currency.Currency) error {
	log.Info().Msgf("App: Doing withdraw for user with login %s. Order ID: %s. Sum: %d", login, orderID, sum)

	orderExist, err := gapp.Storage.IsExistUserOrderWithID(login, orderID)
	if err != nil {
		return err
	}
	if !orderExist {
		return ErrWrongOrderID
	}
	balance, err := gapp.Storage.GetUserBalance(login)
	if err != nil {
		return err
	}
	err = balance.Subtract(sum)
	if errors.Is(err, currency.ErrNegativeValue) {
		return ErrBalanceTooLow
	}
	err = gapp.Storage.SetUserBalance(login, balance)
	if err != nil {
		return err
	}
	withdrawalTime := time.Now()
	newWithdrawal := storage.Withdrawal{OrderID: orderID, Amount: sum, ProcessedAt: withdrawalTime}
	err = gapp.Storage.AddWithdrawal(login, newWithdrawal)
	if err != nil {
		return err
	}
	return nil
}
