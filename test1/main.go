package main

import (
	"fmt"
	"log"
	"os"
	"runtime/pprof"

	"github.com/google/nftables"
)

func main() {

	f, err := os.Create("cpu.pprof")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	c := &nftables.Conn{}

	dump := make(map[string][]*nftables.Chain)

	chains, err := c.ListChains()
	if err != nil {
		panic(err)
	}
	for _, chain := range chains {
		dump[chain.Table.Name] = append(dump[chain.Table.Name], chain)
	}

	for table, chain := range dump {
		fmt.Printf("table ip %s {", table)
		for _, ch := range chain {
			var msg string

			fmt.Printf("\n\tchain %s {", ch.Name)
			if len(ch.Type) > 0 {
				msg = "\n\t\ttype " + string(ch.Type) + " "
				msg = msg + "hook " + fmt.Sprint(ch.Hooknum) + " "
				msg = msg + "priority " + fmt.Sprint(ch.Priority) + "; "
				pol := *ch.Policy
				msg = msg + "policy " + fmt.Sprint(pol) + ";"
			}
			fmt.Printf("%s", msg)
			rules, err := c.GetRule(ch.Table, ch)
			if err != nil {
				panic(err)
			}
			for _, rule := range rules {
				fmt.Printf("\n\t\t")
				for _, expr := range rule.Exprs {
					fmt.Printf("%+v ", expr)
				}
			}

			fmt.Printf("\n\t}\n")
		}
		fmt.Printf("}\n")
	}

}
