package functions

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"scrapi/scrapi/core/structs"
	"scrapi/scrapi/core/utils"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	ENV_VAR_CERTIFICATE_FILE        string = "CERTIFICATE_FILE"
	ENV_VAR_CERTIFICATE_PRIVATE_KEY string = "PRIVATE_KEY"
	ENV_VAR_POSTGRES_HOST           string = "POSTGRES_HOST"
	ENV_VAR_POSTGRES_PORT           string = "POSTGRES_PORT"
	ENV_VAR_POSTGRES_DB             string = "POSTGRES_DB"
	ENV_VAR_POSTGRES_USER           string = "POSTGRES_USER"
	ENV_VAR_POSTGRES_PWD            string = "POSTGRES_PASSWORD"
	LOG_FILE_LOCATION               string = "/var/log"
	UUID_PATTERN                    string = `([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`
	ID_PATTERN                      string = `([0-9]+)`
	FILENAME_PATTERN                string = `([^\/]+)`
)

type MonoConfig[c any, l any, p any, t any, m any] struct {
	Import          c
	Local           l
	CTFTracking     t
	Middleware      m
	PublicDocuments p
}

type ScrapiImpl struct {
	Config *MonoConfig[ConfigImport, ConfigLocal, structs.PublicDocuments, CTFTracker, ConfigMiddleware]
}

type ConfigMiddleware struct {
	Logging struct {
		CurrentDate     string
		RequestLogger   *log.Logger
		LogFileLocation string
	}
	RateLimiting struct {
		PerMinuteLimit int
		Visitors       map[string]*rate.Limiter
		Mu             sync.Mutex
	}
}

type CTFTracker struct {
	Names          []string
	AllocatedNames []string
}

type ConfigImport struct {
	Config struct {
		Postgresql struct {
			Host         string `yaml:"host"`
			Port         int    `yaml:"port"`
			Username     string `yaml:"username"`
			Password     string `yaml:"password"`
			DatabaseName string `yaml:"db_name"`
		} `yaml:"postgresql"`
		Api struct {
			Secret string `yaml:"api_secret"`
		} `yaml:"api"`
		Certificates struct {
			CertificateFile string `json:"certificate_file_path"`
			KeyFile         string `json:"key_file_path"`
		} `json:"certificates"`
	} `yaml:"config"`
}

type ConfigLocal struct {
	HTTP struct {
		Host      string
		HTTPPort  string
		HTTPSPort string
	}
	Mux struct {
		Vars map[*http.Request]map[string]string
	}
	Logging struct {
		WarningLogger   *log.Logger
		InfoLogger      *log.Logger
		ErrorLogger     *log.Logger
		CurrentDate     string
		LogFileLocation string
	}
	JWT struct {
		Issuer string
	}
}

func (c *ScrapiImpl) LogHTTPRequest(RequestInfo *structs.HTTPRequestInfo) {
	Date := utils.GetDate()
	if c.Config.Middleware.Logging.CurrentDate != Date {
		c.Config.Middleware.Logging.CurrentDate = Date
		LogFile := filepath.Join(c.Config.Middleware.Logging.LogFileLocation, "Scrapi-HTTP-Logs-"+c.Config.Middleware.Logging.CurrentDate+".log")
		file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		c.Config.Middleware.Logging.RequestLogger = log.New(file, "", log.Ldate|log.Ltime|log.Lshortfile)
	}
	JSONLogData, err := json.Marshal(RequestInfo)
	if err != nil {
		log.Fatal(err)
	}
	c.Config.Middleware.Logging.RequestLogger.Println(string(JSONLogData[:]))
}

func (c *ScrapiImpl) GetMuxVarInt(r *http.Request) (ID int, Error error) {
	IDString, ok := c.Config.Local.Mux.Vars[r]["id"]
	delete(c.Config.Local.Mux.Vars, r)
	ID, err := strconv.Atoi(IDString)
	if !ok || err != nil {
		Message := "Invalid ID provided"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		return 0, errors.New(strings.ToLower(Message))
	}
	return
}

func (c *ScrapiImpl) GetPoints(TrackableFlagID int) int {
	Deduction := 50
	db := c.Get_DB()
	Flag_Points := make(map[int]int)
	Flag_Points[1] = 5000
	Flag_Points[2] = 10000
	Flag_Points[3] = 15000

	var counter int
	db.QueryRow("SELECT count(*) FROM flags WHERE flag_id_trackable=$1;", TrackableFlagID).Scan(&counter)

	return (Flag_Points[TrackableFlagID] - (counter * Deduction))
}

func JSONResponseMessage(StatusCode int, ErrorMessage string, w http.ResponseWriter, r *http.Request) {
	var http_err structs.CommonMessage
	http_err.Body.Message = ErrorMessage + "."
	w.WriteHeader(StatusCode)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(http_err.Body)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(userDetails structs.UserDetails, providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(userDetails.PasswordHash), []byte(providedPassword))
	return err
}

type JWTClaim struct {
	User_ID  string `json:"id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

func StrContains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (c *ScrapiImpl) generateJWT(user *structs.UserDetails) (string, int64, error) {
	expirationTime := time.Now().Add(1 * time.Hour).UTC().Unix()
	// Create the JWT claims, which includes the username and expiry time
	claims := &JWTClaim{
		User_ID:  strconv.Itoa(user.User_ID),
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime,
			Issuer:    c.Config.Local.JWT.Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(c.Config.Import.Config.Api.Secret))
	if err != nil {
		return "", 0, err
	} else {
		return tokenString, expirationTime, nil
	}
}

func (c *ScrapiImpl) VerifyJWT(r *http.Request) (*structs.UserDetails, error) {
	db := c.Get_DB()
	var ud structs.UserDetails
	JWT := strings.ReplaceAll(r.Header.Get("Authorization"), "Bearer ", "")
	token, err1 := jwt.ParseWithClaims(
		JWT,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(c.Config.Import.Config.Api.Secret), nil
		},
	)
	if err1 != nil {
		return &ud, err1
	}
	claims, ok := token.Claims.(*JWTClaim)
	if !ok {
		return &ud, errors.New("failed to parse claims")
	}
	if claims.StandardClaims.ExpiresAt < time.Now().UTC().Unix() {
		return &ud, errors.New("current JWT has expired")
	}
	if claims.StandardClaims.Issuer != c.Config.Local.JWT.Issuer {
		return &ud, errors.New("invalid issuer")
	}
	row := db.QueryRow("SELECT user_id, username, password, firstname, lastname, mfa_token, role, team_id FROM users WHERE user_id=$1 AND username=$2;", claims.User_ID, claims.Username)
	err2 := row.Scan(&ud.User_ID, &ud.Username, &ud.PasswordHash, &ud.FirstName, &ud.LastName, &ud.MFA, &ud.Role, &ud.Team_ID)
	if err2 != nil {
		return &ud, err2
	}
	return &ud, nil
}

// swagger:route POST /api/login Authenticate AuthRequest
// Authenticate to the API
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	200: AuthResponse
func (c *ScrapiImpl) Authenticate(w http.ResponseWriter, r *http.Request) {
	var ur structs.AuthRequest
	err := json.NewDecoder(r.Body).Decode(&ur.Body)
	if err != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err)
		JSONResponseMessage(http.StatusBadRequest, "Failed to decode body", w, r)
		return
	} else {
		db := c.Get_DB()
		row := db.QueryRow("SELECT * FROM users WHERE username=$1;", ur.Body.Username)
		var userDetails structs.UserDetails

		if err1 := row.Scan(&userDetails.User_ID, &userDetails.Username, &userDetails.PasswordHash, &userDetails.FirstName, &userDetails.LastName, &userDetails.MFA, &userDetails.Role, &userDetails.Token, &userDetails.TokenExp, &userDetails.Team_ID); err1 != nil {
			c.Config.Local.Logging.ErrorLogger.Println(err1)
			JSONResponseMessage(http.StatusBadRequest, "Incorrect user", w, r)
			return
		}

		if ur.Body.PasswordHash != "" {
			if ur.Body.PasswordHash != userDetails.PasswordHash {
				Message := "Incorrect password"
				c.Config.Local.Logging.ErrorLogger.Println(Message)
				JSONResponseMessage(http.StatusBadRequest, Message, w, r)
				return
			}
		} else {
			err2 := CheckPassword(userDetails, ur.Body.Password)
			if err2 != nil {
				c.Config.Local.Logging.ErrorLogger.Println(err2)
				JSONResponseMessage(http.StatusBadRequest, "Incorrect password", w, r)
				return
			}
		}

		if ur.Body.MFA != userDetails.MFA {
			Message := "Invalid MFA token"
			c.Config.Local.Logging.ErrorLogger.Println(Message)
			JSONResponseMessage(http.StatusBadRequest, Message, w, r)
			return
		}
		var response structs.AuthResponse

		if userDetails.Token.Valid && userDetails.TokenExp.Valid && userDetails.TokenExp.Int64 >= time.Now().UTC().Unix() {
			response.Body.Token = userDetails.Token.String
			response.Body.Message = "Current token is still valid."
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.Encode(response.Body)
			return
		} else {
			JWT, Exp, err4 := c.generateJWT(&userDetails)
			if err4 != nil {
				c.Config.Local.Logging.ErrorLogger.Println(err4)
				JSONResponseMessage(http.StatusInternalServerError, "Error generating JWT", w, r)
				return
			} else {
				_, err5 := db.Exec("UPDATE users SET token=$1, token_expiry=$2 WHERE user_id=$3;", JWT, Exp, userDetails.User_ID)
				if err5 != nil {
					c.Config.Local.Logging.ErrorLogger.Println(err5)
					JSONResponseMessage(http.StatusInternalServerError, "Error updating JWT", w, r)
					return
				}
				var (
					flag_id           int
					flag_id_trackable int
					flag_captured     bool
				)
				if strings.Contains(userDetails.Username, "_admin") {
					flag_id_trackable = 3
				} else {
					flag_id_trackable = 1
				}
				response.Body.Token = JWT
				response.Body.Message = "Token refreshed."
				row := db.QueryRow("SELECT flag_id, flag_captured, flag FROM flags WHERE flag_id_trackable=$1 AND team_id=$2;", 1, userDetails.Team_ID)
				if err6 := row.Scan(&flag_id, &flag_captured, &response.Body.Flag); err6 != nil {
					c.Config.Local.Logging.ErrorLogger.Println(err6)
					JSONResponseMessage(http.StatusInternalServerError, "Error retrieving flag", w, r)
					return
				}
				if !flag_captured {
					_, err7 := db.Exec("UPDATE flags SET flag_captured=$1 WHERE flag_id=$2", true, flag_id)
					if err7 != nil {
						c.Config.Local.Logging.ErrorLogger.Println(err7)
						JSONResponseMessage(http.StatusInternalServerError, "Error updating flags", w, r)
						return
					}
					points := c.GetPoints(flag_id_trackable)
					_, err8 := db.Exec("UPDATE teams SET team_points=team_points+$1 WHERE team_id=$2", points, userDetails.Team_ID)
					if err8 != nil {
						c.Config.Local.Logging.ErrorLogger.Println(err8)
						JSONResponseMessage(http.StatusInternalServerError, "Error updating team points", w, r)
						return
					}
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				enc.Encode(response.Body)
				return
			}
		}
	}
}

func (c *ScrapiImpl) SecureSecretRandomGenerator() (Secret string) {
	// The term "SecureRandom" refers to the fact that this secret is not pseudorandom.
	Bytes := make([]byte, 64)
	rand.Read(Bytes)
	Secret = strconv.FormatUint(binary.BigEndian.Uint64(Bytes), 10)
	return
}

func (c *ScrapiImpl) Initialise() {
	c.Config.CTFTracking.Names = []string{"Ivan", "Evan", "Nick", "Paul", "Dave", "Andy", "Alex", "Mick", "Mark", "John", "Luke", "Ruth", "Jess", "Jack", "Lois", "Cass", "Mona", "Lisa", "Emma", "Lola", "Lyra", "Mina", "Greg", "Gary", "Hugh", "Hugo", "Pete", "Mike", "Doug", "Sean"}
	c.Config.Middleware.RateLimiting.Visitors = make(map[string]*rate.Limiter)
	c.Config.Middleware.RateLimiting.PerMinuteLimit = 50
	c.Config.Middleware.Logging.LogFileLocation = LOG_FILE_LOCATION
	c.Config.Import.Config.Api.Secret = c.SecureSecretRandomGenerator() + c.SecureSecretRandomGenerator()
	c.Config.Import.Config.Certificates.CertificateFile = os.Getenv(ENV_VAR_CERTIFICATE_FILE)
	c.Config.Import.Config.Certificates.KeyFile = os.Getenv(ENV_VAR_CERTIFICATE_PRIVATE_KEY)
	c.Config.Import.Config.Postgresql.Host = os.Getenv(ENV_VAR_POSTGRES_HOST)
	c.Config.Import.Config.Postgresql.Port, _ = strconv.Atoi(os.Getenv(ENV_VAR_POSTGRES_PORT))
	c.Config.Import.Config.Postgresql.DatabaseName = os.Getenv(ENV_VAR_POSTGRES_DB)
	c.Config.Import.Config.Postgresql.Username = os.Getenv(ENV_VAR_POSTGRES_USER)
	c.Config.Import.Config.Postgresql.Password = os.Getenv(ENV_VAR_POSTGRES_PWD)
	c.Config.Local.Logging.LogFileLocation = LOG_FILE_LOCATION
	c.Config.Local.Mux.Vars = make(map[*http.Request]map[string]string)
	c.Config.Local.JWT.Issuer = "ScrAPI"
}

// DB set up
func (c *ScrapiImpl) Get_DB() *sql.DB {
	dbinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", c.Config.Import.Config.Postgresql.Host, c.Config.Import.Config.Postgresql.Port, c.Config.Import.Config.Postgresql.Username, c.Config.Import.Config.Postgresql.Password, c.Config.Import.Config.Postgresql.DatabaseName)
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		log.Println("Failed to establish a database connection.", err)
		os.Exit(1)
	}
	return db
}

func (c *ScrapiImpl) GetVisitor(ip string) *rate.Limiter {
	c.Config.Middleware.RateLimiting.Mu.Lock()
	defer c.Config.Middleware.RateLimiting.Mu.Unlock()

	limiter, exists := c.Config.Middleware.RateLimiting.Visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(1*time.Minute/50), 50)
		c.Config.Middleware.RateLimiting.Visitors[ip] = limiter
	}

	return limiter
}

func (c *ScrapiImpl) RateLimiter(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			JSONResponseMessage(http.StatusInternalServerError, "Failed to get IP", w, r)
			return
		}

		limiter := c.GetVisitor(ip)
		if !limiter.Allow() {
			JSONResponseMessage(http.StatusTooManyRequests, "Rate limit exceeded", w, r)
			return
		} else {
			next(w, r)
		}
	})
}

func (c *ScrapiImpl) GeneralLoggingRotateHandler() error {
	Date := utils.GetDate()
	if c.Config.Local.Logging.CurrentDate != Date {
		c.Config.Local.Logging.CurrentDate = Date
		LogFile := filepath.Join(c.Config.Local.Logging.LogFileLocation, "Scrapi-General-Logs-"+c.Config.Local.Logging.CurrentDate+".log")
		file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		c.Config.Local.Logging.InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		c.Config.Local.Logging.WarningLogger = log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
		c.Config.Local.Logging.ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
	return nil
}

func CommonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "no-store, max-age=0")
		w.Header().Add("Pragma", "no-cache")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-Frame-Options", "deny")
		next.ServeHTTP(w, r)
	})
}

func GetSlash(URL string) string {
	Slash := "/"
	if strings.HasSuffix(URL, Slash) {
		return ""
	}
	return Slash
}

func (c *ScrapiImpl) MiddlewareReqInfoAndHeaders(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	RequestInfo := &structs.HTTPRequestInfo{
		Method:    r.Method,
		URI:       r.URL.String(),
		Referer:   r.Header.Get("Referer"),
		UserAgent: r.Header.Get("User-Agent"),
		Time:      utils.GetTime(),
	}
	RequestInfo.IPAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
	c.LogHTTPRequest(RequestInfo)
	w.Header().Add("Cache-Control", "no-store, max-age=0")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("X-Frame-Options", "deny")
	return w
}

func (c *ScrapiImpl) SimpleMiddleware(next http.Handler, methods ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w = c.MiddlewareReqInfoAndHeaders(w, r)
		if utils.StrContains(r.Method, methods) {
			next.ServeHTTP(w, r)
		} else {
			JSONResponseMessage(http.StatusBadRequest, "Invalid method, allowed methods: "+strings.Join(methods[:], ", "), w, r)
			return
		}
	})
}

func (c *ScrapiImpl) CustomMiddleware(BaseURI string, URIPaths []*structs.URIPath) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AlwaysSlash := "/"
		w = c.MiddlewareReqInfoAndHeaders(w, r)
		RegexMatched := false

		for _, URIPath := range URIPaths {
			URL := BaseURI
			if len(URIPath.Variables) == 0 && URIPath.URISuffix == "" && strings.HasSuffix(r.URL.Path, AlwaysSlash) {
				r.URL.Path = strings.TrimSuffix(r.URL.Path, AlwaysSlash)
				URL = strings.TrimSuffix(URL, AlwaysSlash)
			}
			Slash := GetSlash(URL)
			for _, Var := range URIPath.Variables {
				URL = URL + Slash
				if Var.VarPrefix != "" {
					URL = URL + Var.VarPrefix + AlwaysSlash
				}
				if Var.VariableName != "" {
					if Var.VariableName == "filename" {
						URL = URL + FILENAME_PATTERN
					} else {
						URL = URL + ID_PATTERN
					}
				}
				Slash = GetSlash(URL)
			}
			if URIPath.URISuffix != "" {
				URL = URL + Slash + URIPath.URISuffix
			}
			if regexp.MustCompile(`^` + URL + `$`).MatchString(r.URL.Path) {
				if len(URIPath.Variables) > 0 {
					RE := regexp.MustCompile(`^` + URL + `$`)
					Vars := RE.FindStringSubmatch(r.URL.Path)
					VarLength := RE.NumSubexp()
					VarMap := make(map[string]string, VarLength)
					for VarID := range utils.MakeRange(1, VarLength) {
						VarMap[URIPath.Variables[VarID].VariableName] = Vars[VarID+1]
					}
					c.Config.Local.Mux.Vars[r] = VarMap
				}
				if !utils.StrContains(strings.ToUpper(r.Method), URIPath.Methods) {
					JSONResponseMessage(http.StatusBadRequest, "Invalid method, allowed methods: "+strings.Join(URIPath.Methods[:], ", "), w, r)
					return
				}
				URIPath.Next.ServeHTTP(w, r)
				RegexMatched = true
				break
			}
		}

		if !RegexMatched {
			JSONResponseMessage(http.StatusNotFound, "Not Found", w, r)
			return
		}
	})
}

func (c *ScrapiImpl) RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+":"+r.RequestURI, http.StatusMovedPermanently)
}

func (c *ScrapiImpl) Start() *http.ServeMux {
	// Init config
	c.Initialise()

	err := c.GeneralLoggingRotateHandler()
	if err != nil {
		log.Fatal(err)
	}

	// Init the mux router
	router := http.NewServeMux()

	// Swagger Documentation
	router.Handle("/swagger/", http.StripPrefix("/swagger", c.SwaggerHandler(c.Config.PublicDocuments.Swagger.Spec)))
	router.Handle("/", c.SwaggerHandler(c.Config.PublicDocuments.Swagger.Spec))

	const (
		StandardIDVar string = "id"
		POST          string = "POST"
		GET           string = "GET"
	)

	// Get rankings of teams
	router.Handle("/api/rankings", c.SimpleMiddleware(http.HandlerFunc(c.GetRankings), GET))

	// Create New Team
	router.Handle("/api/team/new", c.SimpleMiddleware(http.HandlerFunc(c.CreateTeam), POST))

	// Retrieve Team Flags
	router.Handle("/api/team/flags", c.SimpleMiddleware(http.HandlerFunc(c.GetTeamFlags), GET))

	// Categorise Flag for Extra Points
	TeamFlagBaseURI := "/api/team/flag"
	router.Handle(TeamFlagBaseURI, c.CustomMiddleware(TeamFlagBaseURI, []*structs.URIPath{
		{Variables: []*structs.URIPathVariable{{VariableName: StandardIDVar}}, URISuffix: "categorise", Next: http.HandlerFunc(c.CategoriseTeamFlags), Methods: []string{POST}},
	}))

	// login
	router.Handle("/api/login", c.SimpleMiddleware(http.HandlerFunc(c.Authenticate), POST))

	// Retrieve user details
	UserBaseURI := "/api/user/"
	router.Handle(UserBaseURI, c.CustomMiddleware(UserBaseURI, []*structs.URIPath{
		{Variables: []*structs.URIPathVariable{{VariableName: StandardIDVar}}, URISuffix: "details", Next: http.HandlerFunc(c.GetUserDetails), Methods: []string{GET}},
	}))

	// Retrieve user files
	FileBaseURI := UserBaseURI + "files/"
	router.Handle(FileBaseURI, c.CustomMiddleware(FileBaseURI, []*structs.URIPath{
		{Variables: []*structs.URIPathVariable{{VariableName: "filename"}}, Next: http.HandlerFunc(c.GetUserFiles), Methods: []string{GET}},
	}))

	Quit := make(chan struct{})

	// Capture SIGINT

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan
		close(Quit)
		os.Exit(0)
	}()

	go func() {
		if err := http.ListenAndServe(c.Config.Local.HTTP.Host+":"+c.Config.Local.HTTP.HTTPPort, http.HandlerFunc(c.RedirectToHTTPS)); err != nil {
			log.Fatalf("ListenAndServe error: %v", err)
		}
	}()

	return router
}
