// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type xnDoc struct {
	Hosts []xnHost `xml:"host"`
}

type xnAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type xnTimes struct {
	RTT string `xml:"srtt,attr"`
}

type xnPorts struct {
	Port []xnPort `xml:"port"`
}

type xnPort struct {
	Proto string    `xml:"protocol,attr"`
	Id    string    `xml:"portid,attr"`
	State []xnState `xml:"state"`
}

type xnState struct {
	State string `xml:"state,attr"`
}

type xnHost struct {
	Addrs []xnAddr  `xml:"address"`
	Times []xnTimes `xml:"times"`
	Ports []xnPorts `xml:"ports"`
}

// parseXml reads an XML from a reader and parses Host information out of it.
func parseXml(reader io.Reader) ([]Host, error) {
	doc := xnDoc{}

	dec := xml.NewDecoder(reader)
	derr := dec.Decode(&doc)
	if derr != nil {
		return []Host{}, derr
	}

	var hosts []Host
	for _, xh := range doc.Hosts {
		h := Host{}
		for _, xa := range xh.Addrs {
			switch {
			case xa.Type == "ipv4":
				h.IP = net.ParseIP(xa.Addr)
			}
		}
		for _, xt := range xh.Times {
			i, err := strconv.Atoi(xt.RTT)
			if err != nil {
				continue
			}
			h.RTT = i // microseconds
		}
		for _, xps := range xh.Ports {
			for _, xp := range xps.Port {
				if xp.State[0].State == "open" {
					h.OpenPorts = append(h.OpenPorts, fmt.Sprintf("%s/%s", xp.Proto, xp.Id))
				}
			}
		}
		if h.IP.String() != "" {
			hosts = append(hosts, h)
		}
	}

	return hosts, nil
}

// Host represents a single finding inside the nmap scan results.
type Host struct {
	IP        net.IP
	RTT       int
	OpenPorts []string
}

// ScanType defines the parameters the scan is run with.
type ScanType string

const (
	// ScanHostUp runs an nmap host discovery scan only.
	ScanHostUp ScanType = "HOSTUP"

	// ScanDefaultPorts runs an nmap port scan covering nmap's default ports.
	ScanDefaultPorts = "DEFAULTPORTS"

	// ScanAllPorts runs an nmap port scan covering all ports.
	ScanAllPorts = "ALLPORTS"

	// ScanWebPorts runs an nmap port scan covering port 80 and 443
	ScanWebPorts = "WEBPORTS"
)

// Scan runs an nmap scan against a given network and returns a Host struct for every finding.
func Scan(n *net.IPNet, t ScanType) ([]Host, error) {
	args := []string{
		n.String(), "-oX", "-", "-n", "--open",
		// Basically -T5 with minor tweaks
		"--max-rtt-timeout=300ms",
		"--min-rtt-timeout=50ms",
		"--initial-rtt-timeout=200ms",
		"--max-retries=1",
		"--host-timeout=5m",
	}
	switch t {
	case ScanHostUp:
		args = append(args, "-sP")
	case ScanDefaultPorts:
		args = append(args, "-sT")
		args = append(args, "-p")
	case ScanAllPorts:
		args = append(args, "-sT")
		args = append(args, "-p-")
	case ScanWebPorts:
		args = append(args, "-sT")
		args = append(args, "-p80,443")
	default:
		return []Host{}, fmt.Errorf("unknown scan type: %v", t)
	}
	c := exec.Command("nmap", args...)
	fmt.Printf("running scan: %+v\n", strings.Join(c.Args, " "))
	cout, err := c.Output()
	if err != nil {
		return []Host{}, fmt.Errorf("error during scan: %s", err)
	}

	return parseXml(bytes.NewReader(cout))
}
