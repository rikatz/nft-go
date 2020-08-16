package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
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

		hook, err := ChainHookIntToStr(int(chain.Hooknum))
		if err != nil {
			panic(err)
		}
		msg.WriteString("hook " + hook + " ")
		msg.WriteString("priority " + fmt.Sprint(chain.Priority) + "; ")
		//pol := *chain.Policy
		msg.WriteString("policy " + ChainPolicyIntToStr(int(*chain.Policy)) + ";")
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

// ALL BELOW IS GOING TO BE MOVED TO A HELPERS PACKAGE :)

// ChainHookIntToStr converts an interger hook into its equivalent string
func ChainHookIntToStr(hook int) (string, error) {
	switch hook {
	case unix.NF_INET_PRE_ROUTING:
		return "prerouting", nil
	case unix.NF_INET_LOCAL_IN:
		return "input", nil
	case unix.NF_INET_FORWARD:
		return "forward", nil
	case unix.NF_INET_LOCAL_OUT:
		return "output", nil
	case unix.NF_INET_POST_ROUTING:
		return "postrouting", nil
	default:
		return "", errors.New("Invalid hook detected")
	}
}

// ChainPolicyIntToStr converts an integer policy into its equivalent string
func ChainPolicyIntToStr(hook int) string {
	if hook == 0 {
		return "drop"
	}
	return "accept"
}
