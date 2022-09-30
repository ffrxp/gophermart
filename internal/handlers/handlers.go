package handlers

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ffrxp/gophermart/internal/app"
	"github.com/ffrxp/gophermart/internal/common"
	"github.com/ffrxp/gophermart/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const CookieName = "gophermart"

type Router struct {
	*chi.Mux
	app                 *app.GophermartApp
	secKey              []byte
	processOrdersChan   chan OrderProcessorData
	processingOrdersNum int32
}

var ErrInvalidTokenFormat = errors.New("token has invalid format")
var ErrAccrualSystemServerErr = errors.New("accrual system server error")
var ErrAccrualSystemReqEsceeded = errors.New("accrual system: exceeded the number of requests")

type OrderProcessorData struct {
	orderID   string
	userLogin string
}

func NewRouter(ga *app.GophermartApp) Router {
	r := Router{
		Mux: chi.NewMux(),
		app: ga,
	}
	r.Post("/api/user/register", r.middlewareGzipper(r.registerUser()))
	r.Post("/api/user/login", r.middlewareGzipper(r.loginUser()))
	r.Post("/api/user/orders", r.middlewareGzipper(r.middlewareAuth(r.loadOrderNumber())))
	r.Get("/api/user/orders", r.middlewareGzipper(r.middlewareAuth(r.getUserOrders())))
	r.Get("/api/user/balance", r.middlewareGzipper(r.middlewareAuth(r.getUserBalance())))
	r.Post("/api/user/balance/withdraw", r.middlewareGzipper(r.middlewareAuth(r.doWithdraw())))
	r.Get("/api/user/withdrawals", r.middlewareGzipper(r.middlewareAuth(r.getUserWithdrawals())))

	r.Mux.NotFound(r.badRequest())
	r.Mux.MethodNotAllowed(r.badRequest())

	r.secKey = []byte("some_secret_key")
	r.processOrdersChan = make(chan OrderProcessorData)
	go r.ordersProcessor()

	return r
}

type JWTPayload struct {
	Login string `json:"login"`
}

func (payload JWTPayload) Valid() error {
	return nil
}

type CookieData struct {
	Login []byte
	Token []byte
}

type gzipWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

func (w gzipWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (router *Router) middlewareGzipper(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(`Content-Encoding`) == `gzip` {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				io.WriteString(w, err.Error())
				return
			}
			r.Body = io.NopCloser(gz)
		}
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next(w, r)
			return
		}

		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			io.WriteString(w, err.Error())
			return
		}
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		next(gzipWriter{ResponseWriter: w, Writer: gz}, r)
	}
}

func (router *Router) middlewareAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: authentication")
		userCookie, err := r.Cookie(CookieName)
		if err != nil {
			log.Info().Err(err).Msgf("Authentication failed. Cannot get cookies")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		curCookieValue := CookieData{}
		cookieValueUnescaped, err := url.QueryUnescape(userCookie.Value)
		if err != nil {
			log.Info().Err(err).Msgf("Authentication failed. Cannot unescape cookie value")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		err = json.Unmarshal([]byte(cookieValueUnescaped), &curCookieValue)
		if err != nil {
			log.Info().Err(err).Msgf("Authentication failed. Cannot unmarshal cookies")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		isTokenValid, err := router.VerifyToken(string(curCookieValue.Token), string(curCookieValue.Login))
		if err != nil {
			if errors.Is(err, ErrInvalidTokenFormat) {
				log.Info().Err(err).Msgf("Authentication failed. Invalid token format")
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			log.Info().Err(err).Msgf("Authentication failed. Verification token error")
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if !isTokenValid {
			log.Info().Msgf("Authentication failed. Invalid token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (router *Router) badRequest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (router *Router) registerUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: register user")
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()

		if err != nil {
			log.Error().Err(err).Msgf("Request register user failed.")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ct := r.Header.Get("content-type")
		if ct != "application/json" {
			log.Error().Err(err).Msgf("Request register user failed. Invalid content type of request")
			http.Error(w, "Invalid content type of request", http.StatusBadRequest)
			return
		}
		requestParsedBody := struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}{Login: "", Password: ""}
		if err := json.Unmarshal(body, &requestParsedBody); err != nil {
			log.Error().Err(err).Msgf("Request register user failed. Cannot unmarshal JSON request")
			http.Error(w, "Cannot unmarshal JSON request", http.StatusBadRequest)
			return
		}
		if err := router.app.RegisterUser(requestParsedBody.Login, requestParsedBody.Password); err != nil {
			if errors.Is(err, storage.ErrUserExist) {
				log.Info().Err(err).Msgf("User with login %s already exists", requestParsedBody.Login)
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}
		}
		token, err := router.generateJWTToken(requestParsedBody.Login)
		if err != nil {
			log.Error().Err(err).Msgf("Generate token error. Login %s", requestParsedBody.Login)
		}
		cookie, err := router.createCookie(CookieName, requestParsedBody.Login, token)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		log.Info().Msgf("User with login %s registered", requestParsedBody.Login)
		w.WriteHeader(http.StatusOK)
	}
}

func (router *Router) loginUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: user login")
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()

		if err != nil {
			log.Error().Err(err).Msgf("Request of user login failed.")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ct := r.Header.Get("content-type")
		if ct != "application/json" {
			log.Error().Err(err).Msgf("Request of user login failed. Invalid content type of request")
			http.Error(w, "Invalid content type of request", http.StatusBadRequest)
			return
		}
		requestParsedBody := struct {
			Login    string `json:"login"`
			Password string `json:"password"`
		}{Login: "", Password: ""}
		if err := json.Unmarshal(body, &requestParsedBody); err != nil {
			log.Error().Err(err).Msgf("Request of user login failed. Cannot unmarshal JSON request")
			http.Error(w, "Cannot unmarshal JSON request", http.StatusBadRequest)
			return
		}
		loginPwdIsValid, err := router.app.UserCredentialsIsValid(requestParsedBody.Login, requestParsedBody.Password)
		if err != nil {
			log.Error().Err(err).Msgf("Request of user login failed. Checking user credentials error")
			http.Error(w, "Checking user credentials error", http.StatusInternalServerError)
			return
		}
		if !loginPwdIsValid {
			log.Info().Msgf("Pair of login and password is wrong")
			http.Error(w, "Pair of login and password is wrong", http.StatusUnauthorized)
			return
		}
		token, err := router.generateJWTToken(requestParsedBody.Login)
		if err != nil {
			log.Error().Err(err).Msgf("Generate token error. Login %s", requestParsedBody.Login)
		}
		cookie, err := router.createCookie(CookieName, requestParsedBody.Login, token)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		log.Info().Msgf("User with login %s authenticated", requestParsedBody.Login)
		w.WriteHeader(http.StatusOK)
	}
}

func (router *Router) loadOrderNumber() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: load order number")

		cookieData, err := router.processCookies(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userLogin := string(cookieData.Login)

		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			log.Error().Err(err).Msgf("Request of load order number failed")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ct := r.Header.Get("content-type")
		if ct != "text/plain" {
			log.Error().Err(err).Msgf("Request of load order number failed: invalid content type of request")
			http.Error(w, "Invalid content type of request", http.StatusBadRequest)
			return
		}
		orderID := string(body)
		digitOrderID, err := strconv.ParseInt(orderID, 10, 0)
		if err != nil {
			log.Error().Err(err).Msgf("Request of load order number failed: invalid content type of request")
			http.Error(w, "Invalid content type of request", http.StatusBadRequest)
			return
		}
		if !common.IsValidByLuhnAlg(digitOrderID) {
			log.Error().Err(err).Msgf("Request of load order number failed: invalid order ID format. ID: '%s'", orderID)
			http.Error(w, "Invalid order ID format", http.StatusBadRequest)
			return
		}
		err = router.app.LoadOrder(userLogin, orderID)
		if err != nil {
			if errors.Is(err, app.ErrOrderWasLoaded) {
				w.WriteHeader(http.StatusOK)
				log.Info().Msgf("Load order for user %s with ID %s: order has been already loaded", userLogin, orderID)
				return
			}
			if errors.Is(err, app.ErrAnotherUserOrder) {
				w.WriteHeader(http.StatusConflict)
				log.Info().Msgf("Load order for user %s with ID %s: order was made by another user", userLogin, orderID)
				return
			}
			log.Error().Err(err).Msgf("Request of load order number failed")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		go func() {
			router.processOrdersChan <- OrderProcessorData{orderID, userLogin}
		}()
		log.Info().Msgf("Load order for user %s with ID %s: order process started", userLogin, orderID)
	}
}

func (router *Router) getUserOrders() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: get user orders")

		cookieData, err := router.processCookies(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userLogin := string(cookieData.Login)

		orders, err := router.app.GetUserOrders(userLogin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if orders == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("content-type", "application/json")
		result, err := json.Marshal(orders)
		if err != nil {
			log.Error().Err(err).Msgf("Error marshalling user orders. User name:'%s'", userLogin)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, errWrite := w.Write(result)
		if errWrite != nil {
			log.Error().Err(err).Msgf("Error writing user orders. User name:'%s'", userLogin)
			return
		}
		log.Info().Msgf("getting user orders for user %s complete successfully", userLogin)
	}
}

func (router *Router) getUserBalance() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: get user balance")

		cookieData, err := router.processCookies(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userLogin := string(cookieData.Login)
		balanceData, err := router.app.GetUserBalance(userLogin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		result, err := json.Marshal(balanceData)
		if err != nil {
			log.Error().Err(err).Msgf("Error marshalling balance data for user. User name:'%s'", userLogin)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, errWrite := w.Write(result)
		if errWrite != nil {
			log.Error().Err(err).Msgf("Error writing balance data for user. User name:'%s'", userLogin)
			return
		}
		log.Info().Msgf("getting user balance for user %s complete successfully", userLogin)
	}
}

func (router *Router) doWithdraw() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: do withdraw")

		cookieData, err := router.processCookies(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()

		if err != nil {
			log.Error().Err(err).Msgf("Request of doing withdraw failed")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ct := r.Header.Get("content-type")
		if ct != "application/json" {
			log.Error().Err(err).Msgf("Request of doing withdraw failed: invalid content type of request")
			http.Error(w, "Invalid content type of request", http.StatusBadRequest)
			return
		}
		withdrawReqData := struct {
			OrderID string `json:"order"`
			Sum     int    `json:"sum"`
		}{OrderID: "", Sum: 0}

		if err := json.Unmarshal(body, &withdrawReqData); err != nil {
			log.Error().Err(err).Msgf("Request of doing withdraw failed. Cannot unmarshal JSON request")
			http.Error(w, "Cannot unmarshal JSON request", http.StatusBadRequest)
			return
		}

		userLogin := string(cookieData.Login)
		err = router.app.DoWithdraw(userLogin, withdrawReqData.OrderID, withdrawReqData.Sum)
		if err != nil {
			if errors.Is(err, app.ErrWrongOrderID) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				log.Info().Msgf("Doing withdraw for user %s: wrong order ID", userLogin)
				return
			}
			if errors.Is(err, app.ErrBalanceTooLow) {
				w.WriteHeader(http.StatusPaymentRequired)
				log.Info().Msgf("Doing withdraw for user %s: balance too low", userLogin)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Info().Msgf("Doing withdraw for user %s complete successfully", userLogin)
		w.WriteHeader(http.StatusOK)
	}
}

func (router *Router) getUserWithdrawals() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("handler: get user withdrawals")

		cookieData, err := router.processCookies(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userLogin := string(cookieData.Login)

		withdrawals, err := router.app.GetUserWithdrawals(userLogin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if withdrawals == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("content-type", "application/json")
		result, err := json.Marshal(withdrawals)
		if err != nil {
			log.Error().Err(err).Msgf("Error marshalling user withdrawals. User name:'%s'", userLogin)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, errWrite := w.Write(result)
		if errWrite != nil {
			log.Error().Err(err).Msgf("Error writing user withdrawals. User name:'%s'", userLogin)
			return
		}
		log.Info().Msgf("getting user withdrawals for user %s complete successfully", userLogin)
	}
}

func (router *Router) generateJWTToken(userLogin string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"login": userLogin,
	})

	tokenString, err := token.SignedString(router.secKey)
	return tokenString, err
}

func (router *Router) VerifyToken(token, expectedLogin string) (bool, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, ErrInvalidTokenFormat
		}
		return []byte(router.secKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &JWTPayload{}, keyFunc)
	if err != nil {
		return false, ErrInvalidTokenFormat
	}
	payload, ok := jwtToken.Claims.(*JWTPayload)
	if !ok {
		return false, ErrInvalidTokenFormat
	}
	if payload.Login != expectedLogin {
		return false, nil
	}
	return true, nil
}

func (router *Router) createCookie(cookieName, userName, token string) (*http.Cookie, error) {

	JSONCookieBody, err := json.Marshal(CookieData{[]byte(userName), []byte(token)})
	if err != nil {
		log.Error().Err(err).Msgf("error marshalling cookie. User name:'%s', token:'%s'", userName, token)
		return nil, err
	}
	userCookie := &http.Cookie{
		Name:   cookieName,
		Value:  url.QueryEscape(string(JSONCookieBody)),
		MaxAge: 1200,
	}
	return userCookie, nil
}

func (router *Router) processCookies(r *http.Request) (CookieData, error) {
	curCookieValue := CookieData{}
	userCookie, err := r.Cookie(CookieName)
	if err != nil {
		log.Info().Err(err).Msgf("Process cookie failed. Cannot get cookies")
		return curCookieValue, err
	}
	cookieValueUnescaped, err := url.QueryUnescape(userCookie.Value)
	if err != nil {
		log.Info().Err(err).Msgf("Process cookie failed. Cannot unescape cookie value")
		return curCookieValue, err
	}
	err = json.Unmarshal([]byte(cookieValueUnescaped), &curCookieValue)
	if err != nil {
		log.Info().Err(err).Msgf("Process cookie failed. Cannot unmarshal cookies")
		return curCookieValue, err
	}
	return curCookieValue, nil
}

func (router *Router) ordersProcessor() {
	for orderProcData := range router.processOrdersChan {
		log.Info().Msgf("Orders processor: receive new order from channel. User:%s Order ID:%s",
			orderProcData.userLogin, orderProcData.orderID)
		atomic.AddInt32(&router.processingOrdersNum, 1)
		for router.processingOrdersNum > 10 {
			time.Sleep(100 * time.Millisecond)
		}
		go router.orderProcessor(orderProcData.orderID, orderProcData.userLogin)
	}
}

func (router *Router) orderProcessor(orderID string, userLogin string) {
	log.Info().Msgf("Order processor: start goroutine. Order ID:%s", orderID)
	for {
		resp, err := router.requestToAccrualSystem(orderID)
		if err != nil {
			if errors.Is(err, ErrAccrualSystemServerErr) {
				return
			}
			if errors.Is(err, ErrAccrualSystemReqEsceeded) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		AccrualRespData := struct {
			OrderID string `json:"order"`
			Status  string `json:"status"`
			Accrual int    `json:"accrual"`
		}{OrderID: "", Status: "", Accrual: 0}

		if err := json.Unmarshal(resp, &AccrualRespData); err != nil {
			log.Error().Err(err).Msgf("Request to accrual system failed. Cannot unmarshal JSON response")
			return
		}
		err = router.app.ApplyAccrualSystemData(AccrualRespData.OrderID,
			AccrualRespData.Status,
			AccrualRespData.Accrual,
			userLogin)
		if err != nil {
			return
		}
		if AccrualRespData.Status == "INVALID" || AccrualRespData.Status == "PROCESSED" {
			atomic.AddInt32(&router.processingOrdersNum, -1)
			log.Info().Msgf("Order processor: processing complete. Order ID:%s", orderID)
			return
		}
		// Если обработка не завершена, сделать повтовный запрос позже
		time.Sleep(100 * time.Millisecond)
	}
}

func (router *Router) requestToAccrualSystem(orderID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/orders/%s", router.app.AccrualSystemAddr, orderID), nil)
	if err != nil {
		log.Error().Err(err).Msgf("Request to accrual system: creating request error. Order ID:%s", orderID)
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		log.Error().Err(err).Msgf("Request to accrual system:  error while doing request. Order ID:%s", orderID)
		return nil, err
	}
	if resp.StatusCode == http.StatusInternalServerError {
		log.Error().Msgf("Request to accrual system: internal server error returned. Order ID:%s", orderID)
		return nil, ErrAccrualSystemServerErr
	} else if resp.StatusCode == http.StatusTooManyRequests {
		log.Info().Msgf("Request to accrual system: too many requests. Order ID:%s", orderID)
		return nil, ErrAccrualSystemReqEsceeded
	}
	respBody, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Error().Err(err).Msgf("Request to accrual system: error while reading response. Order ID:%s", orderID)
		return nil, err
	}
	return respBody, nil
}
