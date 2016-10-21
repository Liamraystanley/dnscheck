package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	ldns "github.com/Liamraystanley/go-ldns"
	sempool "github.com/Liamraystanley/go-sempool"
	"github.com/miekg/dns"
)

var recordTypes = [...]string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}

// ^(?:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,})?(?P<domain>(?:(?:[A-Za-z0-9_.-]{2,350}\.[A-Za-z0-9]{2,63})\s+)+)$
var reDomain = regexp.MustCompile(`^[A-Za-z0-9_.-]{2,350}\.[A-Za-z0-9]{2,63}$`)
var reRawDomain = regexp.MustCompile(`^(?:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+)?(?P<domains>[A-Za-z0-9_.\s-]{6,})$`)
var reSpaces = regexp.MustCompile(`^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$`)
var reNewlines = regexp.MustCompile(`[\n\r]+`)

// Host represents an item to look up
type Host struct {
	Name string
	Want string
}

type DNSAnswer struct {
	Query        string
	Want         string
	Raw          []string
	Answers      []string
	Answer       string
	ResponseTime string
	Error        string
	RType        string
	IsMatch      bool
}

type DNSResults struct {
	Request  Request
	Records  Answer
	RType    string
	ScanTime string
}

type Request []*Host
type Answer []*DNSAnswer

func (ans Answer) Len() int {
	return len(ans)
}

func (ans Answer) Less(i, j int) bool {
	// if one is erronous, and one is not
	if ans[i].Error != "" && ans[j].Error == "" {
		return true
	} else if ans[i].Error == "" && ans[j].Error != "" {
		return false
	}

	if ans[i].IsMatch == ans[j].IsMatch {
		return ans[i].Query < ans[j].Query
	}

	if ans[i].IsMatch {
		return false
	}

	return true
}

func (ans Answer) Swap(i, j int) {
	ans[i], ans[j] = ans[j], ans[i]
}

func parseHosts(hosts string) (out []*Host, err error) {
	input := strings.Split(reNewlines.ReplaceAllString(reSpaces.ReplaceAllString(hosts, ""), "\n"), "\n")

	var knownHosts []string

	for i := 0; i < len(input); i++ {
		line := reRawDomain.FindStringSubmatch(reSpaces.ReplaceAllString(input[i], ""))
		if len(line) != 3 {
			return nil, errors.New("erronous input")
		}

		for _, domain := range strings.Split(line[2], " ") {
			if domain == "" {
				return nil, errors.New("erronous input")
			}

			domain = strings.Trim(domain, " ")
			if !reDomain.MatchString(domain) {
				return nil, errors.New("erronous input")
			}

			ip, host := line[1], domain

			if host == "" {
				return nil, errors.New("erronous input")
			}

			// verify it's not already within the list
			var alreadyExists bool
			for k := 0; k < len(knownHosts); k++ {
				if knownHosts[k] == host {
					alreadyExists = true
					break
				}
			}
			if alreadyExists {
				continue // skip it
			}

			// track this host to prevent duplicate checks
			knownHosts = append(knownHosts, host)

			out = append(out, &Host{Name: host, Want: ip})
		}
	}

	return out, nil
}

func fmtTime(t time.Duration) string {
	ms := float32(t.Nanoseconds()) / 1000000.0

	return fmt.Sprintf("%.2fms", ms)
}

func LookupAll(hosts []*Host, servers []string, rtype string) (*DNSResults, error) {
	if len(hosts) > conf.Limit {
		return nil, errors.New("Too many queries to process.")
	}

	if len(servers) == 0 {
		return nil, errors.New("No resolvers configured")
	}

	out := &DNSResults{}
	out.ScanTime = time.Now().Format(time.RFC3339)
	out.Request = hosts
	out.RType = rtype
	var lookupType uint16

	switch rtype {
	case "A":
		lookupType = dns.TypeA
	case "":
		lookupType = dns.TypeA
	case "AAAA":
		lookupType = dns.TypeAAAA
	case "CNAME":
		lookupType = dns.TypeCNAME
	case "MX":
		lookupType = dns.TypeMX
	case "NS":
		lookupType = dns.TypeNS
	case "TXT":
		lookupType = dns.TypeTXT
	default:
		return nil, errors.New("Invalid lookup type")
	}

	pool := sempool.New(conf.Concurrency)
	r, err := ldns.New(servers)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(hosts); i++ {
		pool.Slot()

		go func(host *Host) {
			defer pool.Free()

			result, err := r.Lookup(host.Name, lookupType)
			if err != nil {
				out.Records = append(out.Records, &DNSAnswer{
					Query: host.Name,
					Want:  host.Want,
					RType: rtype,
					Error: err.Error(),
				})
				return
			}

			ans := &DNSAnswer{
				Query:        result.Host,
				Want:         host.Want,
				RType:        result.QueryType(),
				Answer:       result.String(),
				ResponseTime: fmtTime(result.RTT),
			}

			for a := 0; a < len(result.Records); a++ {
				ans.Answers = append(ans.Answers, result.Records[a].String())

				if !ans.IsMatch && (result.Records[a].String() == ans.Want || len(ans.Want) == 0 || lookupType != dns.TypeA) {
					// currently, only A records are comparable. in the future, this should support anything,
					// though it would require the user entering this to compare.
					ans.IsMatch = true
				}
			}

			ans.Answer = result.String()

			out.Records = append(out.Records, ans)
		}(hosts[i])
	}

	pool.Wait()

	sort.Sort(out.Records)

	return out, nil
}
