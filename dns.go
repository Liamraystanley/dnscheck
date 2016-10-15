package main

import (
	"errors"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"time"

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
	Name   string
	WantIP string
}

type DNSAnswer struct {
	Query        string
	WantIP       string
	Answer       string
	ResponseTime string
	Error        string
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

			out = append(out, &Host{Name: host, WantIP: ip})
		}
	}

	return out, nil
}

func LookupAll(hosts []*Host, servers []string, rtype string) (*DNSResults, error) {
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

	for i := 0; i < len(hosts); i++ {
		pool.Slot()

		go func(host *Host) {
			defer pool.Free()

			ans := &DNSAnswer{
				Query:  host.Name,
				WantIP: host.WantIP,
			}

			answers, rtt, err := Lookup(servers, host.Name, lookupType, 3)
			if err != nil {
				ans.Error = err.Error()
				out.Records = append(out.Records, ans)
				return
			}

			for a := 0; a < len(answers); a++ {
				if answers[a] == ans.WantIP || len(ans.WantIP) == 0 {
					ans.IsMatch = true
					break
				}
			}

			ans.Answer = strings.Join(answers, ", ")
			ans.ResponseTime = rtt

			out.Records = append(out.Records, ans)
		}(hosts[i])
	}

	pool.Wait()

	sort.Sort(out.Records)

	return out, nil
}

func Lookup(servers []string, target string, rtype uint16, maxAllowed int) ([]string, string, error) {
	c := dns.Client{
		Timeout: 1000 * time.Millisecond,
	}
	m := dns.Msg{}
	m.SetQuestion(target+".", rtype)
	m.RecursionDesired = true
	c.SingleInflight = true

	var result *dns.MSg
	var t time.Duration
	var err error

	if tries := 0; tries < maxAllowed; tries++ {
		result, t, err = c.Exchange(&m, servers[rand.Intn(len(servers))]+":53")
		if err == nil {
			break
		}
		if err != nil {
			if strings.HasSuffix(err.Error(), "i/o timeout") {
				continue
			}
		}
	}
	if err != nil {
		return nil, "", err
	}
	if result == nil {
		return nil, "", errors.New("unable to obtain a response")
	}

	if len(result.Answer) == 0 {
		return nil, "", errors.New("no results found")
	}

	out := []string{}

	for i := 0; i < len(result.Answer); i++ {
		out = append(out, shortRR(result.Answer[i]))
	}

	return out, t.String(), nil
}

// var recordTypes = [...]string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
func shortRR(r dns.RR) string {
	switch t := r.(type) {
	case *dns.A:
		return t.A.String()
	case *dns.AAAA:
		return t.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(t.Target, ".")
	case *dns.MX:
		return strings.TrimSuffix(t.Mx, ".")
	case *dns.NS:
		return strings.TrimSuffix(t.Ns, ".")
	case *dns.TXT:
		return "\"" + strings.Join(t.Txt, " ") + "\""
	}
	return "unknown response"
}
