package functions

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"scrapi/scrapi/core/structs"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// swagger:route POST /api/team/new TeamManagement NewTeamRequest
// Create a new CTF Team
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	200: NewTeamResponse
func (c *ScrapiImpl) CreateTeam(w http.ResponseWriter, r *http.Request) {
	var (
		tr      structs.NewTeamRequest
		team_id int
	)
	err := json.NewDecoder(r.Body).Decode(&tr.Body)
	if err != nil {
		JSONResponseMessage(http.StatusBadRequest, "Failed to decode body", w, r)
		return
	} else {
		db := c.Get_DB()
		_, err2 := db.Exec("INSERT INTO teams (teamname, team_points) VALUES ($1, $2);", tr.Body.Teamname, 0)
		if err2 != nil {
			if pgerr, ok := err2.(*pq.Error); ok {
				if pgerr.Code == "23505" {
					JSONResponseMessage(http.StatusBadRequest, "Team already exists", w, r)
					return
				}
			}
		} else {
			row := db.QueryRow("SELECT team_id FROM teams WHERE teamname=$1;", tr.Body.Teamname)
			if err := row.Scan(&team_id); err != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error retrieving teamname", w, r)
				return
			}
			random_int, err3 := rand.Int(rand.Reader, big.NewInt(int64(len(c.Config.CTFTracking.Names))))
			if err3 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error establishing CTF user.", w, r)
				return
			}
			random_mfa := "00" + strconv.Itoa(int(random_int.Int64()+10))
			name := c.Config.CTFTracking.Names[random_int.Int64()]
			for StrContains(name, c.Config.CTFTracking.AllocatedNames) {
				name = c.Config.CTFTracking.Names[random_int.Int64()]
			}
			c.Config.CTFTracking.AllocatedNames = append(c.Config.CTFTracking.AllocatedNames, name)
			name = strings.ToLower(name)
			chars := []rune(name)
			var reverse_chars []string
			for i := (len(chars) - 1); i >= 0; i-- {
				reverse_chars = append(reverse_chars, string(chars[i]))
			}
			password := strings.Join(reverse_chars, "")
			hash, err4 := HashPassword(password)
			if err4 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error establishing CTF user.", w, r)
				return
			}
			_, err5 := db.Exec("INSERT INTO users (username, password, firstname, lastname, mfa_token, role, team_id) VALUES ($1, $2, $3, $4, $5, $6, $7);", name, hash, name, name, random_mfa, "user", team_id)
			if err5 != nil {
				if pgerr, ok := err5.(*pq.Error); ok {
					if pgerr.Code == "23505" {
						JSONResponseMessage(http.StatusBadRequest, "User already exists", w, r)
						return
					}
				}
			}
			admin_pass := uuid.New()
			admin_hash, err6 := HashPassword(admin_pass.String())
			admin_mfa := "98" + strconv.Itoa(int(random_int.Int64()+10))
			if err6 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error establishing CTF user.", w, r)
				return
			}
			_, err7 := db.Exec("INSERT INTO users (username, password, firstname, lastname, mfa_token, role, team_id) VALUES ($1, $2, $3, $4, $5, $6, $7);", name+"_admin", admin_hash, "admin", "admin", admin_mfa, "admin", team_id)
			if err7 != nil {
				if pgerr, ok := err7.(*pq.Error); ok {
					if pgerr.Code == "23505" {
						JSONResponseMessage(http.StatusBadRequest, "User already exists", w, r)
						return
					}
				}
			}

			var user_id int
			if err := db.QueryRow("SELECT user_id FROM users WHERE username=$1 AND team_id=$2;", name, team_id).Scan(&user_id); err != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error retrieving teamname", w, r)
				return
			}

			flag_4 := uuid.New().String()

			for i := 1; i <= 4; i++ {
				var flag string
				var flag_category string
				if i == 1 {
					flag_category = "API2:2019"
					flag = uuid.New().String()
				} else if i == 2 {
					flag_category = "API1:2019"
					flag = uuid.New().String()
				} else if i == 3 {
					flag_category = "API7:2019"
					flag = uuid.New().String()
				} else if i == 4 {
					flag_category = "API8:2019"
					flag = flag_4
				}
				_, err8 := db.Exec("INSERT INTO flags (flag, flag_id_trackable, flag_captured, flag_category, flag_category_guessed, team_id, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7);", flag, i, false, flag_category, false, team_id, user_id)
				if err8 != nil {
					if pgerr, ok := err8.(*pq.Error); ok {
						if pgerr.Code == "23505" {
							JSONResponseMessage(http.StatusBadRequest, "User already exists", w, r)
							return
						}
					}
				}
			}

			err9 := os.Mkdir("./teamfiles/"+strconv.Itoa(team_id), 0777)
			if err9 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error creating team directory", w, r)
				return
			}
			f, err10 := os.Create("./teamfiles/" + strconv.Itoa(team_id) + "/flag.txt")
			if err10 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error creating team directory", w, r)
				return
			}
			defer f.Close()
			f.WriteString(flag_4)

			var response structs.NewTeamResponse
			response.Body.Team_ID = team_id
			response.Body.Teamname = tr.Body.Teamname
			response.Body.Username = name
			response.Body.Message = "Welcome to ScrAPI, you have registered your team under the name: " + response.Body.Teamname + ". Two users, one user with lower privileges, and one with administrator privileges, have been generated that are unique to your team, and should be used to complete this CTF. The lower privlege user assigned to your team is: " + name + ". To avoid confusion, the username of the administrator user generated for your team includes: " + name + ". While there are preventative controls in place to prevent your team from having visibility into other teams' users. The use of another team's user, or associated JWT tokens to complete the CTF challenge, will result in another team getting points as points are automatically calculated when a challenge is complete and a flag is subsequently issued. Furthermore, while flags are returned in the API responses relevant to successfully completed challenges, they are automatically tracked, and don't need to be submitted anywhere to be allocated points. Points are also given on a first come, first serve basis, meaning the points returned decrease for each team that completes the same challenge, so the first team to complete a challenge gets the most points. Essentially, points are issued at the same time a flag is issued. Team points and rank can viewed anytime using the GET /api/rankings endpoint. All flags have a UUID format. The /team/flag/{id}/categorise endpoint allows teams to provide the relevant OWASP API Top 10:2019 category for the vulnerability that permitted the attack that granted them the flag. You only get one guess, which if correct, will return additional points."
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.Encode(response.Body)
			return
		}
	}
}

// swagger:route GET /api/team/flags TeamManagement GetTeamFlagsRequest
// Get CTF Team Flags
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	401: CommonMessage
//	200: GetTeamFlagsResponse
func (c *ScrapiImpl) GetTeamFlags(w http.ResponseWriter, r *http.Request) {
	ud, err1 := c.VerifyJWT(r)
	if err1 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err1)
		JSONResponseMessage(http.StatusUnauthorized, "Failed to validate authorisation token", w, r)
		return
	}
	db := c.Get_DB()
	rows, err2 := db.Query("SELECT flag_id, flag FROM flags WHERE team_id=$1 AND flag_captured IS TRUE;", ud.Team_ID)
	if err2 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err2)
		JSONResponseMessage(http.StatusInternalServerError, "Failed to retrieve flag details", w, r)
		return
	}
	defer rows.Close()
	var response structs.GetTeamFlagsResponse
	i := 0
	for rows.Next() {
		var resp_body structs.GetTeamFlagsResponseBody
		if err3 := rows.Scan(&resp_body.Flag_ID, &resp_body.Flag); err3 != nil {
			c.Config.Local.Logging.ErrorLogger.Println(err3)
			JSONResponseMessage(http.StatusInternalServerError, "Failed to retrieve flag details", w, r)
			return
		}
		response.Body = append(response.Body, resp_body)
		i += 1
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(response.Body)
}

// swagger:route GET /api/rankings TeamManagement GetRankings
// Get Rankings
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	401: CommonMessage
//	200: GetRankingsResponse
func (c *ScrapiImpl) GetRankings(w http.ResponseWriter, r *http.Request) {
	db := c.Get_DB()
	rows, err1 := db.Query("SELECT team_id, teamname, team_points FROM teams ORDER BY team_points DESC;")
	if err1 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err1)
		JSONResponseMessage(http.StatusInternalServerError, "Failed to retrieve team details", w, r)
		return
	}
	defer rows.Close()
	var response structs.GetRankingsResponse
	i := 0
	for rows.Next() {
		var resp_body structs.GetRankingsResponseBody
		if err2 := rows.Scan(&resp_body.Team_ID, &resp_body.Teamname, &resp_body.FlagPoints); err2 != nil {
			c.Config.Local.Logging.ErrorLogger.Println(err2)
			JSONResponseMessage(http.StatusInternalServerError, "Failed to retrieve flag details", w, r)
			return
		}
		response.Body = append(response.Body, resp_body)
		i += 1
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(response.Body)
}

// swagger:route POST /api/team/flag/{id}/categorise TeamManagement FlagCategorisationRequest
// Categorise CTF Team Flags for Extra Points. The format is API[number]:2019.
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	401: CommonMessage
//	406: FlagCategoriseMessage
//	200: FlagCategorisationResponse
func (c *ScrapiImpl) CategoriseTeamFlags(w http.ResponseWriter, r *http.Request) {
	Valid_Categories := []string{}
	for i := 1; i <= 10; i++ {
		Valid_Categories = append(Valid_Categories, "API"+strconv.Itoa(i)+":2019")
	}
	ud, err1 := c.VerifyJWT(r)
	if err1 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err1)
		JSONResponseMessage(http.StatusInternalServerError, "Failed to validate authorisation token", w, r)
		return
	}
	flag_id, verifyerr := c.GetMuxVarInt(r)
	if verifyerr != nil {
		c.Config.Local.Logging.ErrorLogger.Println(verifyerr)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	err2 := c.GeneralLoggingRotateHandler()
	if err2 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err2)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	db := c.Get_DB()
	var fr structs.FlagCategorisationRequest
	err3 := json.NewDecoder(r.Body).Decode(&fr.Body)
	if err3 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err3)
		JSONResponseMessage(http.StatusBadRequest, "Failed to decode body", w, r)
		return
	}
	var (
		flag_category         string
		flag_id_trackable     int
		flag_category_guessed bool
		team_id               int
	)
	row := db.QueryRow("SELECT flag_category, team_id, flag_id_trackable, flag_category_guessed FROM flags WHERE flag_id=$1;", flag_id)
	if err4 := row.Scan(&flag_category, &team_id, &flag_id_trackable, &flag_category_guessed); err4 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err4)
		JSONResponseMessage(http.StatusInternalServerError, "Error retrieving flag", w, r)
		return
	}
	if team_id != ud.Team_ID {
		Message := "Invalid rights to perform operation"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusUnauthorized, Message, w, r)
		return
	}
	if !StrContains(fr.Body.Category, Valid_Categories) {
		var fl_err structs.FlagCategoriseMessage
		fl_err.Body.Message = "Invalid OWASP API Top 10 2019 format provided, refer to valid categories and choose carefully... Remember you only get one chance!"
		fl_err.Body.ValidCategories = Valid_Categories
		w.WriteHeader(http.StatusNotAcceptable)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(fl_err.Body)
		return
	}
	if flag_category != fr.Body.Category {
		_, err5 := db.Exec("UPDATE flags SET flag_category_guessed=$1 WHERE flag_id=$2;", true, flag_id)
		if err5 != nil {
			c.Config.Local.Logging.ErrorLogger.Println(err5)
			JSONResponseMessage(http.StatusInternalServerError, "Error updating flag", w, r)
			return
		} else {
			Message := "Incorrect. Sorry no additional points can be collected for this flag for your team"
			c.Config.Local.Logging.ErrorLogger.Println(Message)
			JSONResponseMessage(http.StatusBadRequest, Message, w, r)
			return
		}
	}
	if flag_category_guessed {
		Message := "Flag already guessed"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusBadRequest, Message, w, r)
		return
	}
	var (
		team_name   string
		team_points int
	)
	additional_points := 2500 * flag_id_trackable
	row2 := db.QueryRow("SELECT team_points, teamname FROM teams WHERE team_id=$1;", ud.Team_ID)
	if err6 := row2.Scan(&team_points, &team_name); err6 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err6)
		JSONResponseMessage(http.StatusInternalServerError, "Error retrieving flag", w, r)
		return
	}
	new_team_points := team_points + additional_points
	_, err7 := db.Exec("UPDATE teams SET team_points=team_points+$1 WHERE team_id=$2;", additional_points, ud.Team_ID)
	if err7 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err7)
		JSONResponseMessage(http.StatusInternalServerError, "Error updating team details", w, r)
		return
	}
	_, err8 := db.Exec("UPDATE flags SET flag_category_guessed=$1 WHERE flag_id=$2;", true, flag_id)
	if err8 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err8)
		JSONResponseMessage(http.StatusInternalServerError, "Error updating flag", w, r)
		return
	}
	var response structs.FlagCategorisationResponse
	response.Body.TeamID = ud.Team_ID
	response.Body.TeamName = team_name
	response.Body.FlagPoints = new_team_points
	response.Body.FlagPointsAwarded = additional_points
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(response.Body)
}
