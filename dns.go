package main

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var recordTypes = [...]string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
var reDomain = regexp.MustCompile(`^(?:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,})?(?P<domain>[A-Za-z0-9_.-]{2,350}\.[A-Za-z0-9]{2,63})$`)
var reSpaces = regexp.MustCompile(`^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$`)
var reNewlines = regexp.MustCompile(`[\n\r]+`)

// Host represents an item to look up
type Host struct {
	Name   string
	WantIP string
}

func parseHosts(hosts string) (out []*Host, err error) {
	input := strings.Split(reNewlines.ReplaceAllString(reSpaces.ReplaceAllString(hosts, ""), "\n"), "\n")

	for i := 0; i < len(input); i++ {
		line := reDomain.FindStringSubmatch(reSpaces.ReplaceAllString(input[i], ""))
		if line == nil {
			return nil, errors.New("erronous input")
		}

		ip, host := line[1], line[2]

		if host == "" {
			return nil, errors.New("erronous input")
		}

		out = append(out, &Host{Name: host, WantIP: ip})
	}

	return out, nil
}

type DNSAnswer struct {
	Query        string
	WantIP       string
	Answer       string
	ResponseTime string
	Error        error
}

type DNSResults struct {
	Request  []*Host
	Records  []*DNSAnswer
	RType    string
	ScanTime string
}

func LookupAll(hosts []*Host, server, rtype string) (*DNSResults, error) {
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

	for i := 0; i < len(hosts); i++ {
		answer, rtt, err := Lookup(server, hosts[i].Name, lookupType)

		if err != nil {
			out.Records = append(out.Records, &DNSAnswer{Error: err})
			continue
		}

		out.Records = append(out.Records, &DNSAnswer{
			Query:        hosts[i].Name,
			WantIP:       hosts[i].WantIP,
			Answer:       answer,
			ResponseTime: rtt,
		})
	}

	return out, nil
}

func Lookup(server, target string, rtype uint16) (string, string, error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(target+".", rtype)
	result, t, err := c.Exchange(&m, server+":53")
	if err != nil {
		return "", "", err
	}

	if len(result.Answer) == 0 {
		return "", "", errors.New("no results found")
	}

	out := []string{}

	for i := 0; i < len(result.Answer); i++ {
		out = append(out, shortRR(result.Answer[i]))
	}

	return strings.Join(out, ", "), t.String(), nil
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
