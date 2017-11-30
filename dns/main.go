// dns project main.go
package main

import (
	"flag"
	"lontest"
)

const (
	usage = "usage:longping -h host -x use VxLan "
)

func main() {

	var vx = flag.Bool("x", false, "use VxLan")
	var dn = flag.String("n", "www.baidu.com", "domain name ")
	flag.Parse()

	lontest.SetEntherNet("en1")

	if *vx {
		lontest.VxLanDNS(lontest.DNSHost, *dn)
		return
	}
	lontest.DNSQuery(lontest.DNSHost, *dn)
}
