package structs

// swagger:parameters GetUserDetailsRequest
type GetUserDetailsRequest struct {
	// JWT Authorization Token
	//
	// In: header
	// name: authorization
	Authorization string
	// ID of a user
	//
	// In: path
	ID string `json:"id"`
}

// User details response
// swagger:response GetUserDetailsResponse
type GetUserDetailsResponse struct {
	// User details response
	// In: body
	Body struct {
		// User identifier
		// type: int
		User_ID int `json:"user_id"`
		// Username
		// type: string
		Username     string `json:"username"`
		PasswordHash string `json:"passhash"`
		// First Name
		// type: string
		FirstName string `json:"first_name"`
		// Last Name
		// type: string
		LastName string `json:"last_name"`
		// MFA
		// min: 4
		// max: 4
		// type: string
		MFA string `json:"mfa"`
		// Role
		// type: string
		Role string `json:"role"`
		Flag string `json:"flag"`
	}
}

// swagger:parameters GetUserFilesRequest
type GetUserFilesRequest struct {
	// JWT Authorization Token
	//
	// In: header
	// name: authorization
	Authorization string
	// Filename
	//
	// In: path
	Filename string `json:"filename"`
}

// User files response
// swagger:response GetUserFilesResponse
type GetUserFilesResponse struct {
	// User files response
	// In: body
	Body struct {
		// List of files
		// type: array
		Files []string `json:"files"`
	}
}
