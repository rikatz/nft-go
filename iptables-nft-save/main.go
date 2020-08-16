package main

import (
	"flag"

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

}
