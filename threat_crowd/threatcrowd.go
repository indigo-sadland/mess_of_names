package threat_crowd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const(

	BASEURL = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="
)

type Response struct {
	Subdomains 	[]string 		`json:"subdomains"`
}

// RequestThreat() makes request to the threatcrowd api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequestThreat(domain string) ([]string, error) {

	var response = new(Response)
	url := BASEURL + domain

	// Set up http client and make request.
	httpClient := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(resp.Body)

	// Write response body to the Response structure.
	json.Unmarshal(body, &response)

	// Create list of subdomains.
	a := response.Subdomains
	var ThreatCrowd []string
	counter := 0
	for _, s := range a {
		counter++
		ThreatCrowd = append(ThreatCrowd, s)
	}
	fmt.Printf("[+] THREATCROWD FOUND %d SUBDOMAINS\n", counter)

	return ThreatCrowd, nil

}

