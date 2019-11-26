package handler

import (
	"math"
	"net"

	"github.com/hawell/logger"
	"github.com/oschwald/maxminddb-golang"
)

type GeoIp struct {
	Enable    bool
	CountryDB *maxminddb.Reader
	ASNDB     *maxminddb.Reader
}

type GeoIpConfig struct {
	Enable    bool   `json:"enable,omitempty"`
	CountryDB string `json:"country_db,omitempty"`
	ASNDB     string `json:"asn_db,omitempty"`
}

func NewGeoIp(config *GeoIpConfig) *GeoIp {
	g := &GeoIp{
		Enable: config.Enable,
	}
	var err error
	if g.Enable {
		g.CountryDB, err = maxminddb.Open(config.CountryDB)
		if err != nil {
			logger.Default.Errorf("cannot open maxminddb file %s: %s", config.CountryDB, err)
		}
		g.ASNDB, err = maxminddb.Open(config.ASNDB)
		if err != nil {
			logger.Default.Errorf("cannot open maxminddb file %s: %s", config.ASNDB, err)
		}
	}
	// defer g.db.Close()
	return g
}

func (g *GeoIp) GetSameCountry(sourceIp net.IP, ips []IP_RR) []IP_RR {
	if !g.Enable || g.CountryDB == nil {
		return ips
	}
	_, _, sourceCountry, err := g.GetGeoLocation(sourceIp)
	if err != nil {
		logger.Default.Error("getSameCountry failed")
		return ips
	}

	var result []IP_RR
	if sourceCountry != "" {
		for _, ip := range ips {
			for _, country := range ip.Country {
				if country == sourceCountry {
					result = append(result, ip)
					break
				}
			}
		}
	}
	if len(result) > 0 {
		return result
	}

	for _, ip := range ips {
		if ip.Country == nil || len(ip.Country) == 0 {
			result = append(result, ip)
		} else {
			for _, country := range ip.Country {
				if country == "" {
					result = append(result, ip)
					break
				}
			}
		}
	}
	if len(result) > 0 {
		return result
	}

	return ips
}

func (g *GeoIp) GetSameASN(sourceIp net.IP, ips []IP_RR) []IP_RR {
	if !g.Enable || g.ASNDB == nil {
		return ips
	}
	sourceASN, err := g.GetASN(sourceIp)
	if err != nil {
		logger.Default.Error("getSameASN failed")
		return ips
	}

	var result []IP_RR
	if sourceASN != 0 {
		for _, ip := range ips {
			for _, asn := range ip.ASN {
				if asn == sourceASN {
					result = append(result, ip)
					break
				}
			}
		}
	}
	if len(result) > 0 {
		return result
	}

	for _, ip := range ips {
		if ip.ASN == nil || len(ip.ASN) == 0 {
			result = append(result, ip)
		} else {
			for _, asn := range ip.ASN {
				if asn == 0 {
					result = append(result, ip)
					break
				}
			}
		}
	}
	if len(result) > 0 {
		return result
	}

	return ips
}

func (g *GeoIp) GetMinimumDistance(sourceIp net.IP, ips []IP_RR) []IP_RR {
	if !g.Enable || g.CountryDB == nil {
		return ips
	}
	minDistance := 1000.0
	var dists []float64
	var result []IP_RR
	slat, slong, _, err := g.GetGeoLocation(sourceIp)
	if err != nil {
		logger.Default.Error("getMinimumDistance failed")
		return ips
	}
	for _, ip := range ips {
		destinationIp := ip.Ip
		dlat, dlong, _, _ := g.GetGeoLocation(destinationIp)
		d, err := g.getDistance(slat, slong, dlat, dlong)
		if err != nil {
			d = 1000.0
		}
		if d < minDistance {
			minDistance = d
		}
		dists = append(dists, d)
	}
	for i, ip := range ips {
		if dists[i] == minDistance {
			result = append(result, ip)
		}
	}
	if len(result) > 0 {
		return result
	}
	return ips
}

func (g *GeoIp) getDistance(slat, slong, dlat, dlong float64) (float64, error) {
	deltaLat := (dlat - slat) * math.Pi / 180.0
	deltaLong := (dlong - slong) * math.Pi / 180.0
	slat = slat * math.Pi / 180.0
	dlat = dlat * math.Pi / 180.0

	a := math.Sin(deltaLat/2.0)*math.Sin(deltaLat/2.0) +
		math.Cos(slat)*math.Cos(dlat)*math.Sin(deltaLong/2.0)*math.Sin(deltaLong/2.0)
	c := 2.0 * math.Atan2(math.Sqrt(a), math.Sqrt(1.0-a))

	logger.Default.Debugf("distance = %f", c)

	return c, nil
}

func (g *GeoIp) GetGeoLocation(ip net.IP) (latitude float64, longitude float64, country string, err error) {
	if !g.Enable || g.CountryDB == nil {
		return
	}
	var record struct {
		Location struct {
			Latitude        float64 `maxminddb:"latitude"`
			LongitudeOffset uintptr `maxminddb:"longitude"`
		} `maxminddb:"location"`
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	logger.Default.Debugf("ip : %s", ip)
	if err := g.CountryDB.Lookup(ip, &record); err != nil {
		logger.Default.Errorf("lookup failed : %s", err)
		return 0, 0, "", err
	}
	_ = g.CountryDB.Decode(record.Location.LongitudeOffset, &longitude)
	logger.Default.Debug("lat = ", record.Location.Latitude, " lang = ", longitude, " country = ", record.Country.ISOCode)
	return record.Location.Latitude, longitude, record.Country.ISOCode, nil
}

func (g *GeoIp) GetASN(ip net.IP) (uint, error) {
	var record struct {
		AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
	}
	err := g.ASNDB.Lookup(ip, &record)
	if err != nil {
		logger.Default.Errorf("lookup failed : %s", err)
		return 0, err
	}
	logger.Default.Debug("asn = ", record.AutonomousSystemNumber)
	return record.AutonomousSystemNumber, nil
}
