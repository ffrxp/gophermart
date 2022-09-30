package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rs/zerolog/log"
	"time"
)

type Repository interface {
	Close() error
	AddUser(login string, pwdHash []byte) error
	GetPwdHashForLogin(login string) ([]byte, error)
	GetUserUUID(login string) (string, error)
	GetUserTotalWithdrawal(userLogin string) (int, error)
	GetUserBalance(login string) (int, error)
	GetUserWithdrawals(login string) ([]Withdrawal, error)
	GetUserOrders(login string) ([]Order, error)
	IsExistUserOrderWithID(login string, orderID string) (bool, error)
	GetOrderByID(orderID string) (Order, error)
	AddOrder(order Order) error
	UpdateOrder(orderID string, status string, accrual int) error
	SetUserBalance(login string, balance int) error
	AddWithdrawal(login string, withdrawal Withdrawal) error
}

type databaseStorage struct {
	pool *pgxpool.Pool
}

type Withdrawal struct {
	OrderID     string    `json:"order"`
	Amount      int       `json:"sum"`
	ProcessedAt time.Time `json:"processed_at"`
}

type Order struct {
	ID         string    `json:"number"`
	UserID     string    `json:"-"`
	Status     string    `json:"status"`
	Accrual    int       `json:"accrual"`
	UploadedAt time.Time `json:"uploaded_at"`
}

func (order Order) MarshalJSON() ([]byte, error) {
	type OrderNoAccrual Order
	orderNoAccrual := struct {
		ID         string    `json:"number"`
		UserID     string    `json:"-"`
		Status     string    `json:"status"`
		UploadedAt time.Time `json:"uploaded_at"`
	}{
		ID: order.ID, UserID: order.UserID, Status: order.Status, UploadedAt: order.UploadedAt,
	}
	type OrderAlias Order
	orderCopy := struct {
		OrderAlias
	}{OrderAlias: OrderAlias(order)}

	if order.Accrual == 0 {
		return json.Marshal(orderNoAccrual)
	}
	return json.Marshal(orderCopy)
}

var ErrUserExist = errors.New("storage: user already exists")
var ErrEmptyResult = errors.New("storage: empty result")

func NewDatabaseStorage(source string) (*databaseStorage, error) {
	log.Info().Msgf("Storage: create tables if not exists")
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	dbpool, err := pgxpool.Connect(ctx, source)
	if err != nil {
		log.Panic().Msg("Cannot connect to database")
		return nil, err
	}

	queryCreateUsers := `CREATE TABLE IF NOT EXISTS users
						 (uuid uuid NOT NULL,
						  login character varying(255) NOT NULL,
						  password_hash bytea NOT NULL,
						  balance integer NOT NULL DEFAULT 0,
						  PRIMARY KEY (uuid))`

	if _, err := dbpool.Exec(ctx, queryCreateUsers); err != nil {
		log.Panic().Msg("Cannot create table `users`")
		return nil, err
	}
	queryCreateWithdrawals := `CREATE TABLE IF NOT EXISTS withdrawals
							   (uuid uuid NOT NULL,
								user_uuid uuid NOT NULL,
								order_id character varying(255) NOT NULL,
								amount integer NOT NULL,
								processed_at timestamp with time zone NOT NULL,
								PRIMARY KEY (uuid))`
	if _, err := dbpool.Exec(ctx, queryCreateWithdrawals); err != nil {
		log.Panic().Msg("Cannot create table `withdrawals`")
		return nil, err
	}
	queryCreateOrders := `CREATE TABLE IF NOT EXISTS orders
						  (id character varying(255) NOT NULL,
						   user_uuid uuid NOT NULL,
						   status character varying(255) NOT NULL,
						   accrual integer NOT NULL DEFAULT 0,
						   uploaded_at timestamp with time zone NOT NULL,
						   PRIMARY KEY (id))`
	if _, err := dbpool.Exec(ctx, queryCreateOrders); err != nil {
		log.Panic().Msg("Cannot create table `orders`")
		return nil, err
	}
	return &databaseStorage{dbpool}, nil
}

func (dbs *databaseStorage) Close() error {
	dbs.pool.Close()
	return nil
}

func (dbs *databaseStorage) AddUser(login string, pwdHash []byte) error {
	log.Info().Msgf("Storage: add user. Login:'%s'. Password hash:'%s'", login, pwdHash)
	userExists, err := dbs.isUserExists(login)
	if err != nil {
		return err
	}
	if userExists {
		err := ErrUserExist
		return err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	if _, err := dbs.pool.Exec(ctx,
		"INSERT INTO users (uuid, login, password_hash) VALUES (gen_random_uuid(), $1, $2)", login, pwdHash); err != nil {
		log.Error().Err(err).Msgf("SQL insert user error. Login: %s | Hash password: %s", login, pwdHash)
		return err
	}
	return nil
}

func (dbs *databaseStorage) isUserExists(login string) (bool, error) {
	log.Info().Msgf("Storage: check user existence. Login:'%s'", login)
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	var resultCnt int
	if err := dbs.pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE login = $1", login).Scan(&resultCnt); err != nil {
		log.Error().Err(err).Msgf("Storage checking if user exists error. Login: %s", login)
		return false, err
	}
	if resultCnt > 0 {
		return true, nil
	}
	return false, nil
}

func (dbs *databaseStorage) GetPwdHashForLogin(login string) ([]byte, error) {
	log.Info().Msgf("Storage: get password hash for login. Login:'%s'", login)
	var pwdHash []byte

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	err := dbs.pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE login = $1", login).Scan(&pwdHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for login %s", login)
			return nil, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting password hash for login error. Login: %s", login)
		return nil, err
	}
	return pwdHash, nil
}

func (dbs *databaseStorage) GetUserUUID(login string) (string, error) {
	log.Info().Msgf("Storage: get user UUID for login. Login:'%s'", login)

	var userUUID string
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	err := dbs.pool.QueryRow(ctx, "SELECT uuid FROM users WHERE login = $1", login).Scan(&userUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for select user_uuid for login '%s'", login)
			return "", ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting user_uuid for login error. Login: %s", login)
		return "", err
	}
	return userUUID, nil
}

func (dbs *databaseStorage) GetUserTotalWithdrawal(userLogin string) (int, error) {
	log.Info().Msgf("Storage: get total withdrawal for user '%s'", userLogin)

	userUUID, err := dbs.GetUserUUID(userLogin)
	if err != nil {
		return 0, err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	var totalSum int
	err = dbs.pool.QueryRow(ctx, "SELECT COALESCE(SUM(amount), 0) FROM withdrawals WHERE user_uuid = $1", userUUID).Scan(&totalSum)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for select total withdrawals for user '%s'", userLogin)
			return 0, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting withdrawals for user error. Login: %s", userLogin)
		return 0, err
	}
	return totalSum, nil
}

func (dbs *databaseStorage) GetUserBalance(login string) (int, error) {
	log.Info().Msgf("Storage: get user balance for login. Login:'%s'", login)
	var balance int

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	err := dbs.pool.QueryRow(ctx, "SELECT balance FROM users WHERE login = $1", login).Scan(&balance)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for select balance login '%s'", login)
			return 0, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting balance for login error. Login: %s", login)
		return 0, err
	}
	return balance, nil
}

func (dbs *databaseStorage) SetUserBalance(login string, balance int) error {
	log.Info().Msgf("Storage: set user balance. Login:%s. Balance:%d", login, balance)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	if _, err := dbs.pool.Exec(ctx,
		"UPDATE users SET balance = $1 WHERE login = $2", balance, login); err != nil {
		log.Info().Err(err).Msgf("Storage. Update query error. Login:%s. Balance:%d", login, balance)
		return err
	}
	return nil
}

func (dbs *databaseStorage) GetUserWithdrawals(login string) ([]Withdrawal, error) {
	log.Info().Msgf("Storage: get user withdrawals for login. Login:'%s'", login)

	userUUID, err := dbs.GetUserUUID(login)
	if err != nil {
		return nil, err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	rows, err := dbs.pool.Query(ctx,
		"SELECT order_id, amount, processed_at FROM withdrawals WHERE user_uuid = $1 ORDER BY processed_at", userUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Msgf("Storage. Empty result for select withdrawals for login '%s'", login)
			return nil, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting withdrawals for login error. Login: %s", login)
		return nil, err
	}
	defer rows.Close()

	var withdrawals []Withdrawal
	for rows.Next() {
		var withdrawal Withdrawal
		err = rows.Scan(&withdrawal.OrderID, &withdrawal.Amount, &withdrawal.ProcessedAt)
		if err != nil {
			log.Info().Err(err).Msgf("Storage. Error while scan select results of withdrawals for login '%s'", login)
			return nil, err
		}
		withdrawals = append(withdrawals, withdrawal)
	}
	err = rows.Err()
	if err != nil {
		log.Info().Err(err).Msgf("Storage. Error while process select results of withdrawals for login '%s'", login)
		return nil, err
	}
	log.Info().Msgf("Storage. Storage getting withdrawals for login '%s' complete. Withdrawals number:'%d'", login, len(withdrawals))
	return withdrawals, nil
}

func (dbs *databaseStorage) GetUserOrders(login string) ([]Order, error) {
	log.Info().Msgf("Storage: get user orders for login. Login:'%s'", login)

	userUUID, err := dbs.GetUserUUID(login)
	if err != nil {
		return nil, err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	rows, err := dbs.pool.Query(ctx,
		"SELECT id, status, accrual, uploaded_at FROM orders WHERE user_uuid = $1 ORDER BY uploaded_at", userUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for select orders for login '%s'", login)
			return nil, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting orders for login error. Login: %s", login)
		return nil, err
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		err = rows.Scan(&order.ID, &order.Status, &order.Accrual, &order.UploadedAt)
		if err != nil {
			log.Info().Err(err).Msgf("Storage. Error while scan select results of orders for login '%s'", login)
			return nil, err
		}
		order.UserID = userUUID
		orders = append(orders, order)
	}
	err = rows.Err()
	if err != nil {
		log.Info().Err(err).Msgf("Storage. Error while process select results of orders for login '%s'", login)
		return nil, err
	}
	return orders, nil
}

func (dbs *databaseStorage) IsExistUserOrderWithID(login string, orderID string) (bool, error) {
	log.Info().Msgf("Storage: check existence user order by ID. Login:'%s'. Order:%s", login, orderID)

	userUUID, err := dbs.GetUserUUID(login)
	if err != nil {
		return false, err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	var counter int
	err = dbs.pool.QueryRow(ctx, "SELECT COUNT(*) FROM orders WHERE id = $1 and user_uuid = $2", orderID, userUUID).Scan(&counter)
	if err != nil {
		log.Error().Err(err).Msgf("Storage check existence user order by ID error. Login: %s. Order:%s", login, orderID)
		return false, err
	}
	if counter == 0 {
		return false, nil
	}
	return true, nil
}

func (dbs *databaseStorage) AddOrder(order Order) error {
	log.Info().Msgf("Storage: add order. Order ID:%s", order.ID)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	if _, err := dbs.pool.Exec(ctx,
		"INSERT INTO orders (id,user_uuid,status,accrual,uploaded_at) VALUES ($1, $2, $3, $4, $5)",
		order.ID, order.UserID, order.Status, order.Accrual, order.UploadedAt); err != nil {
		log.Error().Err(err).Msgf("SQL insert order error. Order ID:%s", order.ID)
		return err
	}
	return nil
}

func (dbs *databaseStorage) UpdateOrder(orderID string, status string, accrual int) error {
	log.Info().Msgf("Storage: update order. Order ID:%s", orderID)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()

	if _, err := dbs.pool.Exec(ctx,
		"UPDATE orders SET status = $1, accrual = $2 WHERE id = $3",
		status, accrual, orderID); err != nil {
		log.Error().Err(err).Msgf("SQL update order error. Order ID:%s", orderID)
		return err
	}
	return nil
}

func (dbs *databaseStorage) GetOrderByID(orderID string) (Order, error) {
	log.Info().Msgf("Storage: get order by ID. Order:%s", orderID)

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	var order Order
	err := dbs.pool.QueryRow(ctx, "SELECT id, user_uuid, status, accrual, uploaded_at FROM orders WHERE id = $1", orderID).
		Scan(&order.ID, &order.UserID, &order.Status, &order.Accrual, &order.UploadedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info().Err(err).Msgf("Storage. Empty result for getting order by ID '%s'", orderID)
			return order, ErrEmptyResult
		}
		log.Error().Err(err).Msgf("Storage getting order by ID error. Order:%s", orderID)
		return order, err
	}
	return order, nil
}

func (dbs *databaseStorage) AddWithdrawal(login string, withdrawal Withdrawal) error {
	log.Info().Msgf("Storage: add withdrawal. Login:'%s'. Withdrawal data: order ID:%s|sum:%d",
		login, withdrawal.OrderID, withdrawal.Amount)

	userUUID, err := dbs.GetUserUUID(login)
	if err != nil {
		return err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*2)
	defer cancelFunc()
	if _, err := dbs.pool.Exec(ctx,
		"INSERT INTO withdrawals (uuid, user_uuid, order_id, amount, processed_at) VALUES (gen_random_uuid(), $1, $2, $3, $4)",
		userUUID, withdrawal.OrderID, withdrawal.Amount, withdrawal.ProcessedAt); err != nil {
		log.Error().Err(err).Msgf("SQL insert user error. Login:'%s'. Withdrawal data: order ID:%s|sum:%d",
			login, withdrawal.OrderID, withdrawal.Amount)
		return err
	}
	return nil
}
