package handler

import (
	"log"
	"net"
	"testing"

	"fmt"
	"github.com/hawell/logger"
	"strconv"
)

func TestGeoIpAutomatic(t *testing.T) {
	sip := [][]string{
		{"212.83.32.45", "DE", "213.95.10.76"},
		{"80.67.163.250", "FR", "62.240.228.4"},
		{"178.18.89.144", "NL", "46.19.36.12"},
		{"206.108.0.43", "CA", "154.11.253.242"},
		{"185.70.144.117", "DE", "213.95.10.76"},
		{"62.220.128.73", "CH", "82.220.3.51"},
	}

	dip := [][]string{
		{"82.220.3.51", "CH"},
		{"192.30.252.225", "US"},
		{"213.95.10.76", "DE"},
		{"94.76.229.204", "GB"},
		{"46.19.36.12", "NL"},
		{"46.30.209.1", "DK"},
		{"91.239.97.26", "SI"},
		{"14.1.44.230", "NZ"},
		{"52.76.214.87", "SG"},
		{"103.31.84.12", "MV"},
		{"212.63.210.241", "SE"},
		{"154.11.253.242", "CA"},
		{"128.139.197.81", "IL"},
		{"194.190.198.13", "RU"},
		{"84.88.14.229", "ES"},
		{"79.110.197.36", "PL"},
		{"175.45.73.66", "AU"},
		{"62.240.228.4", "FR"},
		{"200.238.130.54", "BR"},
		{"13.113.70.195", "JP"},
		{"37.252.235.214", "AT"},
		{"185.87.111.13", "FI"},
		{"52.66.51.117", "IN"},
		{"193.198.233.217", "HR"},
		{"118.67.200.190", "KH"},
		{"103.6.84.107", "HK"},
		{"78.128.211.50", "CZ"},
		{"87.238.39.42", "NO"},
		{"37.148.176.54", "BE"},
	}

	cfg := GeoIpConfig{
		Enable:    true,
		CountryDB: "../geoCity.mmdb",
	}
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	g := NewGeoIp(&cfg)

	for i := range sip {
		dest := new(IP_RRSet)
		for j := range dip {
			_, _, cc, _ := g.GetGeoLocation(net.ParseIP(dip[j][0]))
			if cc != dip[j][1] {
				t.Fail()
			}
			r := IP_RR{
				Ip: net.ParseIP(dip[j][0]),
			}
			dest.Data = append(dest.Data, r)
		}
		dest.Ttl = 100
		ips := g.GetMinimumDistance(net.ParseIP(sip[i][0]), dest.Data)
		log.Println("[DEBUG]", sip[i][0], " ", ips[0].Ip.String(), " ", len(ips))
		if sip[i][2] != ips[0].Ip.String() {
			t.Fail()
		}
	}
}

func TestGetSameCountry(t *testing.T) {
	sip := [][]string{
		{"212.83.32.45", "DE", "1.2.3.4"},
		{"80.67.163.250", "FR", "2.3.4.5"},
		{"154.11.253.242", "", "3.4.5.6"},
		{"127.0.0.1", "", "3.4.5.6"},
	}

	cfg := GeoIpConfig{
		Enable:    true,
		CountryDB: "../geoCity.mmdb",
	}
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	g := NewGeoIp(&cfg)

	for i := range sip {
		var dest IP_RRSet
		dest.Data = []IP_RR{
			{Ip: net.ParseIP("1.2.3.4"), Country: []string{"DE"}},
			{Ip: net.ParseIP("2.3.4.5"), Country: []string{"FR"}},
			{Ip: net.ParseIP("3.4.5.6"), Country: []string{""}},
		}
		ips := g.GetSameCountry(net.ParseIP(sip[i][0]), dest.Data)
		if len(ips) != 1 {
			t.Fail()
		}
		log.Println("[DEBUG]", sip[i][1], sip[i][2], ips[0].Country, ips[0].Ip.String())
		if ips[0].Country[0] != sip[i][1] || ips[0].Ip.String() != sip[i][2] {
			t.Fail()
		}
	}

}

func TestGetSameASN(t *testing.T) {
	sip := []string{
		"212.83.32.45",
		"80.67.163.250",
		"154.11.253.242",
		"127.0.0.1",
	}

	dip := IP_RRSet{
		Data: []IP_RR{
			{Ip: net.ParseIP("1.2.3.4"), ASN: []uint{47447}},
			{Ip: net.ParseIP("2.3.4.5"), ASN: []uint{20766}},
			{Ip: net.ParseIP("3.4.5.6"), ASN: []uint{852}},
			{Ip: net.ParseIP("4.5.6.7"), ASN: []uint{0}},
		},
	}

	res := [][]string{
		{"47447", "1.2.3.4"},
		{"20766", "2.3.4.5"},
		{"852", "3.4.5.6"},
		{"0", "4.5.6.7"},
	}
	cfg := GeoIpConfig{
		Enable: true,
		ASNDB:  "../geoIsp.mmdb",
	}

	g := NewGeoIp(&cfg)

	for i := range sip {
		ips := g.GetSameASN(net.ParseIP(sip[i]), dip.Data)
		if len(ips) != 1 {
			t.Fail()
		}
		if strconv.Itoa(int(ips[0].ASN[0])) != res[i][0] || ips[0].Ip.String() != res[i][1] {
			t.Fail()
		}
	}

}

/*
82.220.3.51 9044 CH
192.30.252.225 36459 US
213.95.10.76 12337 DE
94.76.229.204 29550 GB
46.19.36.12 196752 NL
46.30.209.1 51468 DK
91.239.97.26 198644 SI
14.1.44.230 45177 NZ
52.76.214.87 16509 SG
103.31.84.12 7642 MV
212.63.210.241 30880 SE
154.11.253.242 852 CA
128.139.197.81 378 IL
194.190.198.13 2118 RU
84.88.14.229 13041 ES
79.110.197.36 35179 PL
175.45.73.66 4826 AU
62.240.228.4 8426 FR
200.238.130.54 10881 BR
13.113.70.195 16509 JP
37.252.235.214 42473 AT
185.87.111.13 201057 FI
52.66.51.117 16509 IN
193.198.233.217 2108 HR
118.67.200.190 7712 KH
103.6.84.107 36236 HK
78.128.211.50 2852 CZ
87.238.39.42 39029 NO
37.148.176.54 34762 BE
212.83.32.45 47447 DE
80.67.163.250 20766 FR
178.18.89.144 35470 NL
206.108.0.43 393424 CA
185.70.144.117 200567 DE
62.220.128.73 6893 CH
*/
func printCountryASN() {
	ips := []string{
		"82.220.3.51",
		"192.30.252.225",
		"213.95.10.76",
		"94.76.229.204",
		"46.19.36.12",
		"46.30.209.1",
		"91.239.97.26",
		"14.1.44.230",
		"52.76.214.87",
		"103.31.84.12",
		"212.63.210.241",
		"154.11.253.242",
		"128.139.197.81",
		"194.190.198.13",
		"84.88.14.229",
		"79.110.197.36",
		"175.45.73.66",
		"62.240.228.4",
		"200.238.130.54",
		"13.113.70.195",
		"37.252.235.214",
		"185.87.111.13",
		"52.66.51.117",
		"193.198.233.217",
		"118.67.200.190",
		"103.6.84.107",
		"78.128.211.50",
		"87.238.39.42",
		"37.148.176.54",
		"212.83.32.45",
		"80.67.163.250",
		"178.18.89.144",
		"206.108.0.43",
		"185.70.144.117",
		"62.220.128.73",
	}
	cfg := GeoIpConfig{
		Enable:    true,
		ASNDB:     "../geoIsp.mmdb",
		CountryDB: "../geoCity.mmdb",
	}

	g := NewGeoIp(&cfg)

	for _, ip := range ips {
		asn, _ := g.GetASN(net.ParseIP(ip))
		_, _, c, _ := g.GetGeoLocation(net.ParseIP(ip))
		fmt.Println(ip, asn, c)
	}
}
