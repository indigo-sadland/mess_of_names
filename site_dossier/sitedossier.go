package site_dossier

import (
	"fmt"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"
)

const(

	BASEURL = "http://www.sitedossier.com/parentdomain/"

)

var (

	pageNum string
	SiteDossier []string

)


// RequestDossier() makes request to the threatcrowd api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequestDossier(domain string) ([]string, error) {

	for {

		URL := BASEURL  + domain + "/" + pageNum

		// Set up http client and make request.
		httpClient := &http.Client{}
		req, _ := http.NewRequest("GET", URL, nil)
		req.Header.Set("Content-Type", "text/html; charset=UTF-8")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		body, _ := ioutil.ReadAll(resp.Body)

		flag := parseHTML(string(body), domain)
		if flag  {
			// Sleep is to prevent triggering captcha.
			time.Sleep(30 * time.Second)
			continue
		} else {
			break
		}

	}

	counter := len(SiteDossier)
	fmt.Printf("[+] DNSSCAN FOUND %d SUBDOMAINS\n", counter )

	return SiteDossier, nil
}

func parseHTML (htmlBody ,domain string) bool {
	var flag bool

	z := html.NewTokenizer(strings.NewReader(htmlBody))
	for {
		tt := z.Next()

		switch tt {
		case html.ErrorToken:
			// If we have more page then return true.
			switch {
			case flag:
				return true
			default:
				return false
			}
		case html.StartTagToken, html.EndTagToken:
			token := z.Token()
			if "a" == token.Data {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						// Check if there is more pages available.
						if strings.Contains(attr.Val, "/parentdomain/") {
							base := path.Base(attr.Val)
							flag = true
							pageNum = base
						}
						if strings.Contains(attr.Val,domain) {
							if strings.Contains(attr.Val, "/parentdomain") {
								continue
							}
							subdomain := strings.Trim(attr.Val, "/site/")
							SiteDossier = append(SiteDossier,subdomain)
						}

					}

				}
			}

		}
	}
}

