package model

// BlacklistCheckResult
type BlacklistCheckResult struct {
	Domain      string            `json:"domain"`
	IP          string            `json:"ip"`
	Time        int64             `json:"time"`
	Tested      int               `json:"tested"`
	Passed      int               `json:"passed"`
	Invalid     int               `json:"invalid"`
	Blacklisted int               `json:"blacklisted"`
	BlackList   []BlacklistDetail `json:"black_list"`
}

// BlacklistDetail
type BlacklistDetail struct {
	Blacklist string `json:"blacklist"`
	Response  string `json:"response"`
	Time      int64  `json:"time"`
}
