package functions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"scrapi/scrapi/core/structs"
	"strconv"
	"strings"
)

// swagger:route GET /api/user/files/{filename} UserManagement GetUserFilesRequest
// Get User Files
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	401: CommonMessage
//	200: GetUserFilesResponse
func (c *ScrapiImpl) GetUserFiles(w http.ResponseWriter, r *http.Request) {
	ud, err1 := c.VerifyJWT(r)
	db := c.Get_DB()
	if err1 != nil {
		Message := "Failed to validate authorisation token"
		c.Config.Local.Logging.ErrorLogger.Println(err1)
		JSONResponseMessage(http.StatusUnauthorized, Message, w, r)
		return
	}

	if ud.Role != "admin" {
		Message := "Insufficient permissions"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusUnauthorized, Message, w, r)
		return
	}

	filename, ok := c.Config.Local.Mux.Vars[r]["filename"]
	delete(c.Config.Local.Mux.Vars, r)
	if !ok {
		Message := "Invalid filename provided"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusInternalServerError, Message, w, r)
		return
	}

	err0 := c.GeneralLoggingRotateHandler()
	if err0 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err0)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}

	if strings.Contains(filename, " ") {
		if _, e := regexp.MatchString(`[a-zA-Z0-9\.\*]+\s\&\&\s(ls|cat|pwd|uname|whoami)(\s([\-a-zA-Z0-9\.]+))?`, filename); e != nil {
			JSONResponseMessage(http.StatusUnauthorized, "Invalid filename", w, r)
			return
		}
	}

	if strings.Contains(filename, "&& cat flag.txt") {
		var flag_captured bool
		row := db.QueryRow("SELECT flag_captured FROM flags WHERE flag_id_trackable=$1 AND team_id=$2;", 4, ud.Team_ID)
		if err := row.Scan(&flag_captured); err != nil {
			JSONResponseMessage(http.StatusInternalServerError, "Error retrieving flag", w, r)
			return
		}
		if !flag_captured {
			points := c.GetPoints(4)
			_, err2 := db.Exec("UPDATE teams SET team_points=team_points+$1 WHERE team_id=$2", points, ud.Team_ID)
			if err2 != nil {
				JSONResponseMessage(http.StatusInternalServerError, "Error updating team points", w, r)
				return
			}
		}
	}
	var response structs.GetUserFilesResponse
	command := `cd teamfiles/` + strconv.Itoa(ud.Team_ID) + `/ && ls ` + filename

	binary, lookErr := exec.LookPath("bash")
	if lookErr != nil {
		c.Config.Local.Logging.ErrorLogger.Println(lookErr)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	args := []string{"bash", "-c", command}
	cmd := &exec.Cmd{
		Path: binary,
		Args: args,
	}
	out, err2 := cmd.CombinedOutput()
	if err2 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err2)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	response.Body.Files = strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(response.Body)
}

// swagger:route GET /api/user/{id}/details UserManagement GetUserDetailsRequest
// Get User Details
//
// responses:
//
//	500: CommonMessage
//	400: CommonMessage
//	401: CommonMessage
//	200: GetUserDetailsResponse
func (c *ScrapiImpl) GetUserDetails(w http.ResponseWriter, r *http.Request) {
	ud, err1 := c.VerifyJWT(r)
	if err1 != nil {
		Message := "Failed to validate authorisation token"
		c.Config.Local.Logging.ErrorLogger.Println(err1)
		JSONResponseMessage(http.StatusUnauthorized, Message, w, r)
		return
	}
	user_id, verifyerr := c.GetMuxVarInt(r)
	if verifyerr != nil {
		c.Config.Local.Logging.ErrorLogger.Println(verifyerr)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	fmt.Println(user_id, ud.User_ID)
	if (user_id != ud.User_ID) && ((user_id - 1) != ud.User_ID) {
		Message := "Insufficient permissions"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusUnauthorized, Message, w, r)
		return
	}
	err0 := c.GeneralLoggingRotateHandler()
	if err0 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err0)
		JSONResponseMessage(http.StatusInternalServerError, "Unknown error", w, r)
		return
	}
	db := c.Get_DB()
	var team_id int
	row := db.QueryRow("SELECT user_id, username, password, firstname, lastname, mfa_token, role, team_id FROM users WHERE user_id=$1;", user_id)
	var res structs.GetUserDetailsResponse

	err2 := row.Scan(&res.Body.User_ID, &res.Body.Username, &res.Body.PasswordHash, &res.Body.FirstName, &res.Body.LastName, &res.Body.MFA, &res.Body.Role, &team_id)
	if err2 != nil {
		c.Config.Local.Logging.ErrorLogger.Println(err2)
		JSONResponseMessage(http.StatusInternalServerError, "Failed to retrieve user details", w, r)
		return
	}

	if team_id != ud.Team_ID {
		Message := "Failed to retrieve user details"
		c.Config.Local.Logging.ErrorLogger.Println(Message)
		JSONResponseMessage(http.StatusInternalServerError, Message, w, r)
		return
	}

	if ud.Role != "admin" && res.Body.Role == "admin" {
		var flag_captured bool
		row := db.QueryRow("SELECT flag, flag_captured FROM flags WHERE flag_id_trackable=$1 AND user_id=$2;", 2, ud.User_ID)
		row.Scan(&res.Body.Flag, &flag_captured)
		if !flag_captured {
			points := c.GetPoints(2)
			_, err3 := db.Exec("UPDATE flags SET flag_captured=$1 WHERE team_id=$2;", true, ud.Team_ID)
			if err3 != nil {
				c.Config.Local.Logging.ErrorLogger.Println(err3)
				JSONResponseMessage(http.StatusInternalServerError, "Error updating flag", w, r)
				return
			}
			_, err4 := db.Exec("UPDATE teams SET team_points=team_points+$1 WHERE team_id=$2;", points, ud.Team_ID)
			if err4 != nil {
				c.Config.Local.Logging.ErrorLogger.Println(err4)
				JSONResponseMessage(http.StatusInternalServerError, "Error updating team points", w, r)
				return
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(res.Body)
}
