package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/google/nftables/expr"
	helpers "github.com/rikatz/nft-go/helpers"

	"github.com/google/nftables"
)

var (
	tablename string
	nfconn    *nftables.Conn
)

func main() {
	flag.StringVar(&tablename, "t", "", "What table to save? Empty means all tables")
	flag.Parse()

	nfconn = &nftables.Conn{}

	chainsMap := make(map[string][]*nftables.Chain)

	chains, err := nfconn.ListChains()
	if err != nil {
		panic(err)
	}

	for _, chain := range chains {
		if tablename != "" && chain.Table.Name != tablename {
			continue
		}
		chainsMap[chain.Table.Name] = append(chainsMap[chain.Table.Name], chain)
	}

	wg := &sync.WaitGroup{}

	for table, chain := range chainsMap {
		wg.Add(1)
		go getChain(table, chain, wg)

	}
	wg.Wait()

}

func getChain(table string, chain []*nftables.Chain, wg *sync.WaitGroup) {
	defer wg.Done()

	var dumpTable bytes.Buffer
	dumpTable.WriteString(fmt.Sprintf("*%s\n", table))

	// First we write the chain name to keep compability
	// Ref.: https://git.netfilter.org/iptables/tree/iptables/xtables-save.c?h=master#n93
	for _, ch := range chain {
		// TODO: We're dropping the counters here, need to know how to gather :)
		dumpTable.WriteString(fmt.Sprintf(":%s", ch.Name, strings.ToUpper(helpers.ChainPolicyIntToStr(ch.Policy))))
	}

	for _, ch := range chain {
		dumpTable.WriteString(getRule(ch))
	}
	dumpTable.WriteString("COMMIT\n")

	// Move this to outside and only write if no error is found
	fmt.Printf(dumpTable.String())
}

func getRule(chain *nftables.Chain) string {
	var msg bytes.Buffer

	msg.WriteString(fmt.Sprintf("-A %s ", chain.Name))

	if len(chain.Type) > 0 {
		msg.WriteString("\n\t\ttype " + string(chain.Type) + " ")

		hook, err := helpers.ChainHookIntToStr(int(chain.Hooknum))
		if err != nil {
			panic(err)
		}
		msg.WriteString("hook " + hook + " ")
		msg.WriteString("priority " + fmt.Sprint(chain.Priority) + "; ")
		//pol := *chain.Policy
		msg.WriteString("policy " + helpers.ChainPolicyIntToStr(int(*chain.Policy)) + ";")
	}

	rules, err := nfconn.GetRule(chain.Table, chain)
	if err != nil {
		panic(err)
	}
	for _, rule := range rules {
		msg.WriteString("\n\t\t")
		for _, expr := range rule.Exprs {
			msg.WriteString(fmt.Sprintf("%+v %T", expr, expr))
		}
	}

	msg.WriteString("\n\t}\n")
	return msg.String()

}

func getAndValidateRule(table *nftables.Table, chain *nftables.Chain,
	wg *sync.WaitGroup, mutex *sync.RWMutex,
	chainsMap map[*nftables.Chain][]*nftables.Rule) {

	defer wg.Done()
	rules, err := nfconn.GetRule(chain.Table, chain)
	if err != nil {
		panic(err)
	}

	for _, rule := range rules {
		err := validateExpr(rule.Exprs)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	mutex.Lock()
	chainsMap[chain] = rules
	mutex.Unlock()
}

func validateExpr(exprs []expr.Any) error {

	for _, item := range exprs {

		switch item.(type) {
		case *expr.Bitwise, *expr.Meta, *expr.Cmp,
			*expr.Counter, *expr.Payload, *expr.Verdict,
			*expr.Lookup, *expr.Immediate:
			return nil
		case *expr.Limit:
			return errors.New("Incompatible table has been found") // TODO: Change this
		}
	}
	return errors.New("Incompatible table has been found")
}
