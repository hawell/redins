package handler

import (
	"log"
	"net"
	"testing"

	"github.com/hawell/logger"
)

func TestWeight(t *testing.T) {
	logger.Default = logger.NewLogger(&logger.LogConfig{}, nil)

	// distribution
	ips := []IP_RR{
		{Ip: net.ParseIP("1.2.3.4"), Weight: 4},
		{Ip: net.ParseIP("2.3.4.5"), Weight: 1},
		{Ip: net.ParseIP("3.4.5.6"), Weight: 5},
		{Ip: net.ParseIP("4.5.6.7"), Weight: 10},
	}
	n := make([]int, 4)
	for i := 0; i < 100000; i++ {
		x := ChooseIp(ips, true)
		switch ips[x].Ip.String() {
		case "1.2.3.4":
			n[0]++
		case "2.3.4.5":
			n[1]++
		case "3.4.5.6":
			n[2]++
		case "4.5.6.7":
			n[3]++
		}
	}
	if n[0] > n[2] || n[2] > n[3] || n[1] > n[0] {
		t.Fail()
	}

	// all zero
	for i := range ips {
		ips[i].Weight = 0
	}
	n[0], n[1], n[2], n[3] = 0, 0, 0, 0
	for i := 0; i < 100000; i++ {
		x := ChooseIp(ips, true)
		switch ips[x].Ip.String() {
		case "1.2.3.4":
			n[0]++
		case "2.3.4.5":
			n[1]++
		case "3.4.5.6":
			n[2]++
		case "4.5.6.7":
			n[3]++
		}
	}
	for i := 0; i < 4; i++ {
		if n[i] < 2000 && n[i] > 3000 {
			t.Fail()
		}
	}

	// some zero
	n[0], n[1], n[2], n[3] = 0, 0, 0, 0
	ips[0].Weight, ips[1].Weight, ips[2].Weight, ips[3].Weight = 0, 5, 7, 0
	for i := 0; i < 100000; i++ {
		x := ChooseIp(ips, true)
		switch ips[x].Ip.String() {
		case "1.2.3.4":
			n[0]++
		case "2.3.4.5":
			n[1]++
		case "3.4.5.6":
			n[2]++
		case "4.5.6.7":
			n[3]++
		}
	}
	log.Println(n)
	if n[0] > 0 || n[3] > 0 {
		t.Fail()
	}

	// weighted = false
	n[0], n[1], n[2], n[3] = 0, 0, 0, 0
	ips[0].Weight, ips[1].Weight, ips[2].Weight, ips[3].Weight = 0, 5, 7, 0
	for i := 0; i < 100000; i++ {
		x := ChooseIp(ips, false)
		switch ips[x].Ip.String() {
		case "1.2.3.4":
			n[0]++
		case "2.3.4.5":
			n[1]++
		case "3.4.5.6":
			n[2]++
		case "4.5.6.7":
			n[3]++
		}
	}
	log.Println(n)
	for i := 0; i < 4; i++ {
		if n[i] < 2000 && n[i] > 3000 {
			t.Fail()
		}
	}
}
