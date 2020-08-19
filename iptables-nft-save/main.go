package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/google/nftables/expr"

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

	// We create a Map with map[tableName][]*nftables.Chain
	chainsMap := make(map[*nftables.Chain][]*nftables.Rule)
	chains, err := nfconn.ListChains()
	if err != nil {
		panic(err)
	}

	wg := &sync.WaitGroup{}
	mutex := &sync.RWMutex{}
	for _, chain := range chains {
		if tablename != "" && chain.Table.Name != tablename {
			continue
		}
		wg.Add(1)
		go getAndValidateRule(chain.Table, chain, wg, mutex, chainsMap)
	}
	wg.Wait()

	fmt.Printf("%v", chainsMap)
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
