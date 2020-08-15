This repo is only for benchmarking stuff!

# The idea
It seems some C programs using libnft are suffering a lot. So I've decided to rewrite some slow things in Go and using the Google nftables library just for fun.


# Benchmark
In an environment with >50k rules in nftables (basically from Calico) we can see the following difference in a system with minimum load

* Running the nft from the system
```
time sudo nft list ruleset > /dev/null

real    0m6,814s
user    0m2,774s
sys     0m4,023s

``` 

* Running this program, that basically does the same and I really don't know if this is the right way (probably using goroutines for each chain would make it FASTER but who knows ¯\\_(ツ)_/¯

```
time sudo output/iptables-nft-go >/dev/null

real    0m3,841s
user    0m4,744s
sys     0m1,796s
```

We can see that Go spends half the time in Kernel/Netlink communication that C. This still can be improved and needs some profilling.

# TODO
* Convert the structures, integers, etc etc to readable things (as the nft list ruleset)
* Our worst case is iptables-nft-save, so why not write a iptables-nft-save in Go and try to restore with the original C program


