package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

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
	logger.Println("successfully wrote data to '%s.tmp'", fn)

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

	if err := db.Verify(); err != nil {
		logger.Fatalf("error while attempting to verify geoip data: %s", err)
	}

	logger.Println("verification complete. good to go!")
}

func GeoIPLookup(addr string) error { return nil }
