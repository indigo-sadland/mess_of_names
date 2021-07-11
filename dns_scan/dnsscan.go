package dns_scan

import (
	"fmt"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const(

	BASEURL = "https://www.dnsscan.cn/dns.html"

)

var (

	pageNum = 1
	DnsScan []string

)


// RequestDnsscan() makes request to the threatcrowd api endpoint,parses response
// and creates list of subdomains for the given domain.
func RequestDnsscan(domain string) ([]string, error) {

	for {

		URL := BASEURL + "?keywords=" + domain + "&page=" + strconv.Itoa(pageNum)

		// Set up http client and make request.
		httpClient := &http.Client{}
		data := url.Values{}
		data.Add("ecmsfrom", "")
		data.Add("show", "")
		data.Add("pageNum", "")
		data.Add("classid", "")
		data.Add("keywords", domain)
		req, _ := http.NewRequest("POST", URL, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "https://www.dnsscan.cn/dns.html?keywords=")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		body, _ := ioutil.ReadAll(resp.Body)

		if strings.Contains(string(body), `你所浏览的页面暂时无法访问`) {
			fmt.Printf("[-] DNSSCAN COULDN'T FOUND ANYTHING :c. TRY MANUAL SEARCH ON THE WEBSITE\n" )
			return nil, nil
		}

		flag := parseHTML(string(body), domain)
		if flag  {
			continue
		} else {
			break
		}
	}

	counter := len(DnsScan)
	fmt.Printf("[+] DNSSCAN FOUND %d SUBDOMAINS\n", counter )

	return DnsScan, nil
}

func parseHTML (htmlBody ,domain string) bool {
	z := html.NewTokenizer(strings.NewReader(htmlBody))
	for {
		tt := z.Next()

		switch tt {
		case html.ErrorToken:
			// After we done with html page we need to check whether there is more.
			switch {
			case strings.Contains(htmlBody, `<div id="page" class="pagelist">`):
				if strings.Contains(htmlBody, `<li class="disabled"><span>&raquo;</span></li>`) {
					return false
				} else {
					pageNum = pageNum + 1
					return true
				}
			default:
				pageNum = pageNum + 1
				return true
			}
		case html.StartTagToken, html.EndTagToken:
			token := z.Token()
			if "a" == token.Data {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						if strings.Contains(attr.Val, "/dns.html"){
							continue
						}
						if strings.Contains(attr.Val,domain) {
							reg := regexp.MustCompile(`^https?\://`)
							subdomain := reg.ReplaceAllString(attr.Val, "${1}")
							DnsScan = append(DnsScan,subdomain)
						}

					}

				}
			}

		}
	}
}

