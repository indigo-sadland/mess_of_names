package main

import (
	"flag"
	"fmt"
	"github.com/indigo-sadland/MessOfNames/alien_vault"
	"github.com/indigo-sadland/MessOfNames/dns_scan"
	"github.com/indigo-sadland/MessOfNames/hacker_target"
	"github.com/indigo-sadland/MessOfNames/security_trails"
	"github.com/indigo-sadland/MessOfNames/site_dossier"
	"github.com/indigo-sadland/MessOfNames/threat_crowd"
	"os"
)

func RequestAll(domain, api string)  {

	fmt.Printf("[*] COLLECTING SUBDOMAINS FOR <<%s>>. PLEASE STAND BY :)\n", domain)

	AlienVaualt, err := alien_vault.RequestAlien(domain)
	if err != nil {
		fmt.Println(err)
	}

	DnsScan, err := dns_scan.RequestDnsscan(domain)
	if err != nil {
		fmt.Println(err)
	}

	HackerTarget, err := hacker_target.RequesHackerTarget(domain)
	if err != nil {
		fmt.Println(err)
	}

	SecurityTrails, err := security_trails.RequestTrails(domain, api)
	if err != nil {
		fmt.Println(err)
	}

	SiteDossier, err := site_dossier.RequestDossier(domain)
	if err != nil {
		fmt.Println(err)
	}

	ThreadCrowd, err := threat_crowd.RequestThreat(domain)
	if err != nil {
		fmt.Println(err)
	}


	AllSubdomains := operateSlices(AlienVaualt, DnsScan, HackerTarget, SecurityTrails, SiteDossier, ThreadCrowd)

	counter := len(AllSubdomains)
	fmt.Printf("[*] ALL DONE! FOUND %d UNIQUE SUBDOMAINS FOR %s:\n", counter, domain)
	for _, subdom := range AllSubdomains {
		fmt.Println(subdom)
	}


}

func operateSlices(slices...[]string) []string {
	var mergedSlice []string

	for _, oneSlice := range slices {
		mergedSlice = append(mergedSlice, oneSlice...)
	}

	subdomainList := removeDuplicateValues(mergedSlice)

	return subdomainList
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

func main()  {

	InputDomain := flag.String("domain", "", "Domain to work with.")
	SecTrailsKey := flag.String("api","", "Security Trails API key (If you want to use this service in scan).")
	flag.Parse()


	if *InputDomain == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	RequestAll(*InputDomain, *SecTrailsKey)
}
