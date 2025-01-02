package structs

// Flag categorisation error message
// swagger:response FlagCategoriseMessage
type FlagCategoriseMessage struct {
	// Error response message
	// In: body
	Body struct {
		// Error message
		// type: string
		Message string `json:"message"`
		// Error message
		// type: array
		ValidCategories []string `json:"valid_categories"`
	}
}

// swagger:parameters GetTeamFlagsRequest
type GetTeamFlagsRequest struct {
	// JWT Authorization Token
	//
	// In: header
	// name: authorization
	Authorization string
}

// Team flags response
// swagger:response GetTeamFlagsResponse
type GetTeamFlagsResponse struct {
	// In: body
	Body []GetTeamFlagsResponseBody
}

// swagger:enum GetTeamFlagsResponseBody
type GetTeamFlagsResponseBody struct {
	Flag_ID int    `json:"flag_id"`
	Flag    string `json:"flag"`
}

// swagger:parameters FlagCategorisationRequest
type FlagCategorisationRequest struct {
	// JWT Authorization Token
	//
	// In: header
	// name: authorization
	Authorization string
	// ID of a flag
	//
	// In: path
	ID string `json:"id"`
	// Flag Categorisation Request Body
	// In: body
	Body struct {
		// name: flag
		// type: string
		// required: true
		Flag string `json:"flag"`
		// name: category
		// type: string
		// required: true
		Category string `json:"category"`
	}
}

// Flag categorisation response
// swagger:response FlagCategorisationResponse
type FlagCategorisationResponse struct {
	// In: body
	Body struct {
		// name: team_id
		// type: int
		// required: true
		TeamID int `json:"team_id"`
		// name: team_name
		// type: string
		// required: true
		TeamName string `json:"team_name"`
		// name: flag_points_total
		// type: int
		// required: true
		FlagPoints int `json:"team_points_total"`
		// name: flag_points_new
		// type: int
		// required: true
		FlagPointsAwarded int `json:"team_points_added"`
	}
}

// swagger:parameters NewTeamRequest
type NewTeamRequest struct {
	// In: body
	Body struct {
		// name: team_name
		// type: string
		// required: true
		Teamname string `json:"team_name"`
	}
}

// New team response
// swagger:response NewTeamResponse
type NewTeamResponse struct {
	// In: body
	Body struct {
		Team_ID  int    `json:"team_id"`
		Teamname string `json:"team_name"`
		Message  string `json:"message"`
		Username string `json:"ctf_user"`
	}
}

// Team rankings response
// swagger:response GetRankingsResponse
type GetRankingsResponse struct {
	// In: body
	Body []GetRankingsResponseBody
}

// swagger:enum GetRankingsResponseBody
type GetRankingsResponseBody struct {
	// Team identifier
	// type: int
	Team_ID int `json:"team_id"`
	// Team name
	// type: string
	Teamname string `json:"team_name"`
	// Team flag points
	// type: int
	FlagPoints int `json:"team_points"`
}
