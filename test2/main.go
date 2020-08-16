package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/google/nftables"
)

var c *nftables.Conn

func main() {

	f, err := os.Create("cpu.pprof")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	c = &nftables.Conn{}

	dump := make(map[string][]*nftables.Chain)

	chains, err := c.ListChains()
	if err != nil {
		panic(err)
	}
	for _, chain := range chains {
		dump[chain.Table.Name] = append(dump[chain.Table.Name], chain)
	}

	wg := &sync.WaitGroup{}

	for table, chain := range dump {
		wg.Add(1)
		go getChain(table, chain, wg)

	}
	wg.Wait()

}

func getChain(table string, chain []*nftables.Chain, wg *sync.WaitGroup) {
	defer wg.Done()

	var dumpTable bytes.Buffer
	dumpTable.WriteString(fmt.Sprintf("table ip %s {", table))

	for _, ch := range chain {
		dumpTable.WriteString(getRule(ch))
	}
	dumpTable.WriteString("}\n")
	fmt.Printf(dumpTable.String())
}

func getRule(chain *nftables.Chain) string {
	var msg bytes.Buffer

	msg.WriteString(fmt.Sprintf("\n\tchain %s {", chain.Name))

	if len(chain.Type) > 0 {
		msg.WriteString("\n\t\ttype " + string(chain.Type) + " ")
		msg.WriteString("hook " + fmt.Sprint(chain.Hooknum) + " ")
		msg.WriteString("priority " + fmt.Sprint(chain.Priority) + "; ")
		pol := *chain.Policy
		msg.WriteString("policy " + fmt.Sprint(pol) + ";")
	}

	rules, err := c.GetRule(chain.Table, chain)
	if err != nil {
		panic(err)
	}
	for _, rule := range rules {
		msg.WriteString("\n\t\t")
		for _, expr := range rule.Exprs {
			msg.WriteString(fmt.Sprintf("%+v ", expr))
		}
	}

	msg.WriteString("\n\t}\n")
	return msg.String()

}
