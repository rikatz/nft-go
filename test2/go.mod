module github.com/rikatz/iptables-nft-go

go 1.15

require (
	github.com/google/nftables v0.0.0-20200802175506-c25e4f69b425
	github.com/rikatz/nft-go/helpers v0.0.0-20200816195809-747bfc3ffc01
	github.com/sbezverk/nftableslib v0.0.0-20200402150358-c20bed91f482
	golang.org/x/sys v0.0.0-20200814200057-3d37ad5750ed
)

replace "github.com/google/nftables" v0.0.0-20200802175506-c25e4f69b425 => /home/rkatz/git/nftables
