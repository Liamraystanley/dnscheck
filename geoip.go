package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// GeoIPUpdateCheck checks for updates to the local Maxmind geolocation database
func GeoIPUpdateCheck(fn string) {
	curSeconds := time.Now().UnixNano() / int64(time.Second)
	stat, err := os.Stat(fn)
	if err == nil {
		// check to see if it's valid
		_, err := maxminddb.Open(fn)
		if err != nil {
			logger.Printf("unable to open geoip db '%s': %s", fn, err)
			GeoIPDownload(fn)
			return
		}

		// assume it exists, check to see if it's updated.
		diff := curSeconds - (stat.ModTime().UnixNano() / int64(time.Second))

		// less than a week
		if diff < 604800 {
			return
		}
	}

	// assume it either doesn't exist, or it's too old, and we need to download/ungzip it.
	GeoIPDownload(fn)
}

// GeoIPDownload downloads the Maxmind geolocation database locally, and gunzips it
func GeoIPDownload(fn string) {
	logger.Println("fetching new geoip data")

	// create or truncate if already exists
	logger.Printf("creating '%s.tmp' to store tmp data", fn)
	tmpfile, err := os.Create(fn + ".tmp")
	if err != nil {
		logger.Fatalf("unable to create '%s.tmp': %s", fn, err)
	}
	defer tmpfile.Close()

	logger.Println("downloading geoip data from Maxmind now...")
	// http://lw.liam.sh/GeoLite2-City.mmdb.gz for testing, since it is ratelimited.
	resp, err := http.Get("http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz")
	if err != nil {
		logger.Fatalf("unable to fetch geoip data: %s", err)
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	logger.Println("request completed successfully")

	logger.Printf("writing compressed geoip data to '%s.tmp' now", fn)
	_, err = io.Copy(tmpfile, resp.Body)
	if err != nil {
		logger.Fatalf("unable to write geoip data to '%s.tmp':%s", fn, err)
	}
	logger.Printf("successfully wrote data to '%s.tmp'", fn)

	// now, decompress it

	// new file to save the db to
	file, err := os.Create(fn)
	if err != nil {
		logger.Fatalf("unable to create '%s' to write gunzipped geoip data: %s", fn, err)
	}

	// re-seek the tmp file, since we wrote to it.
	_, _ = tmpfile.Seek(0, 0)

	logger.Println("attempting to decompress downloaded data...")
	r, err := gzip.NewReader(tmpfile)
	if err != nil {
		logger.Fatalf("unable to instantiate gunzip reader: %s", err)
	}

	_, err = io.Copy(file, r)
	if err != nil {
		logger.Fatalf("unable to write gunzipped geoip data to '%s': %s", fn, err)
	}
	defer r.Close()

	logger.Println("successfully decompressed geoip data")

	// ensure that the tmp file is cleaned up
	defer os.Remove(fn + ".tmp")

	logger.Println("attempting to verify geoip data now...")
	db, err := maxminddb.Open(fn)
	if err != nil {
		logger.Fatalf("error while attempting to verify geoip data: %s", err)
	}
	defer db.Close()

	if err := db.Verify(); err != nil {
		logger.Fatalf("error while attempting to verify geoip data: %s", err)
	}

	logger.Println("verification complete. good to go!")
}

// IPSearch is the struct->tag search query to search throughthe Maxmind DB
type IPSearch struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Code  string            `maxminddb:"iso_code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Location struct {
		Lat      float64 `maxminddb:"latitude"`
		Long     float64 `maxminddb:"longitude"`
		TimeZone string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Subdivisions []struct {
		Code  string            `maxminddb:"iso_code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Traits struct {
		Proxy bool `maxminddb:"is_anonymous_proxy"`
	} `maxminddb:"traits"`

	// RegisteredCountry struct {
	// 	Code  string            `maxminddb:"iso_code"`
	// 	Names map[string]string `maxminddb:"names"`
	// } `maxminddb:"registered_country"`
	// RepresentedCountry struct {
	// 	Code  string            `maxminddb:"iso_code"`
	// 	Names map[string]string `maxminddb:"names"`
	// 	Type  string            `maxminddb:"type"`
	// } `maxminddb:"represented_country"`
}

// IPResult contains the geolocation and host information for an IP
type IPResult struct {
	City          string
	Subdivision   string
	Country       string
	CountryCode   string
	Continent     string
	ContinentCode string
	Lat           float64
	Long          float64
	Timezone      string
	PostalCode    string
	Proxy         bool
	Hosts         []string
}

// IPLookup does a geoip lookup of an IP address
func IPLookup(addr string) (*IPResult, error) {
	// TODO: This should probably have some form of daily IP cache (invalidates in 24h?)
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("address provided is not a valid ip: %s", addr)
	}

	db, err := maxminddb.Open(conf.GeoDb)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var results IPSearch

	err = db.Lookup(ip, &results)
	if err != nil {
		return nil, err
	}
	res := &IPResult{
		City:          results.City.Names["en"],
		Country:       results.Country.Names["en"],
		CountryCode:   results.Country.Code,
		Continent:     results.Continent.Names["en"],
		ContinentCode: results.Continent.Code,
		Lat:           results.Location.Lat,
		Long:          results.Location.Long,
		Timezone:      results.Location.TimeZone,
		PostalCode:    results.Postal.Code,
		Proxy:         results.Traits.Proxy,
	}

	var subdiv []string
	for i := 0; i < len(results.Subdivisions); i++ {
		subdiv = append(subdiv, results.Subdivisions[i].Names["en"])
	}
	res.Subdivision = strings.Join(subdiv, ", ")

	if names, err := net.LookupAddr(addr); err == nil {
		for i := 0; i < len(names); i++ {
			// these are FQDN's where absolute hosts contain a suffixed "."
			res.Hosts = append(res.Hosts, strings.TrimSuffix(names[i], "."))
		}
	}

	fmt.Printf("%#v\n", res)

	return res, nil
}
