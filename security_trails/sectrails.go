package security_trails

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const(


	BASEURL = "https://api.securitytrails.com/v1/domain/"
)

type Response struct {
	Subdomains 	[]string 		`json:"subdomains"`
	Meta 		map[string]bool `json:"meta"`
}

// RequestTrails() makes request to the security trails api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequestTrails(domain, api string) ([]string, error) {

	if api == "" {
		fmt.Println("[-] SECURITY TRAILS: API KEY WAS NOT PROVIDED")
		return nil, nil
	}

	var response = new(Response)
	url := BASEURL + domain + "/subdomains?children_only=false&include_inactive=true"

	// Set up http client and make request.
	httpClient := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("APIKEY", api)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(resp.Body)

	// Write response body to the Response structure.
	json.Unmarshal(body, &response)

	// Check if we run out free requests.
	limit := response.Meta
	if limit["limit_reached"]{
		err = fmt.Errorf("[-] SECURITY TRAILS: REACHED LIMIT OF REQUESTS :c")
		return nil, err
	}

	// Create list of subdomains.
	a := response.Subdomains
	var SecTrailsList []string
	for _, s := range a {
		subDom := s + "." + domain
		SecTrailsList = append(SecTrailsList, subDom)
	}
	counter := len(SecTrailsList)
	fmt.Printf("[+] SECURITY TRAILS FOUND %d SUBDOMAINS\n", counter)

	return SecTrailsList, nil

}



