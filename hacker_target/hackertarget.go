package hacker_target

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	BASEURL = "https://api.hackertarget.com/hostsearch/?q="
)

// RequesHackerTarget() makes request to the hackertarget api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequesHackerTarget(domain string) ([]string, error) {

	urlPath := BASEURL + domain

	// Set up http client and make request.
	httpClient := &http.Client{}
	req, _ := http.NewRequest("GET", urlPath , nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(resp.Body)

	var HackerTarget []string
	split := strings.Split(string(body), "\n")

	// Parse the string body into []string.
	for _, u := range split {
		// Split IP from the subdomain string.
		raw := strings.SplitAfter(u, ",")
		subdom := strings.Split(raw[0], ",")
		HackerTarget = append(HackerTarget, subdom[0])
	}

	counter := len(HackerTarget)

	fmt.Printf("[+] HACKERTARGET FOUND %d SUBDOMAINS\n", counter)

	return HackerTarget, nil

}
