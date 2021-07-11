package alien_vault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const(

	BASEURL = "https://otx.alienvault.com/api/v1/indicators/domain/"
)

type Response struct {
	PassiveDns []Inner `json:"passive_dns"`
}

type Inner struct {
	Subdomains string	`json:"hostname"`
}

// RequestAlien() makes request to the alienvault api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequestAlien(domain string) ([]string, error) {

	var response = new(Response)
	url := BASEURL + domain + "/passive_dns"

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
	a := response.PassiveDns
	var rawList []string
	for _, s := range a {
		rawList = append(rawList, s.Subdomains)
	}

	AlienVault := removeDuplicateValues(rawList)

	counter := len(AlienVault)

	fmt.Printf("[+] ALIENVAULT FOUND %d SUBDOMAINS\n", counter)

	return AlienVault, nil

}

func removeDuplicateValues(stringSlice []string)  []string {

	keys := make(map[string]bool)
	subdomainList := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. Else we jump on another element.
	for _, e := range stringSlice {
		if _, value := keys[e]; !value {
			keys[e] = true
			subdomainList = append(subdomainList, e)
		}
	}

	return subdomainList

}
