This repo is only for benchmarking stuff!

# The idea
It seems some C programs using libnft are suffering a lot. So I've decided to rewrite some slow things in Go and using the Google nftables library just for fun.


# Benchmark
In an environment with >50k rules in nftables (basically from Calico) we can see the following difference in a system with minimum load

* Running the nft from the system
```
time nft list ruleset > /dev/null

real    0m7,211s
user    0m2,930s
sys     0m4,276s
``` 

* [TEST 1](test1/) - Running this program, that basically does the same as nft list ruleset without any optimization ¯\\\_(ツ)\_/¯ - IT IS A 80% IMPROVEMENT, WITH 100% IN KERNEL TIME :)

```
time test1/output/iptables-nft-go  > /dev/null

real    0m4,021s
user    0m4,145s
sys     0m2,085s
```

* [TEST 2](test2/) - Go routines + bytes.Buffer for string concatenation, thanks to @amandahla who is THE LIGHT OF MY LIFE :)

```
time test2/output/iptables-nft-go  > /dev/null

real    0m1,518s
user    0m2,519s
sys     0m1,175s
```

THIS IS 1/4 OF THE ORIGINAL TIME (400% OF IMPROVEMENT) 

# TODO
* Convert the structures, integers, etc etc to readable things (as the nft list ruleset)
* Our worst case is iptables-nft-save, so why not write a iptables-nft-save in Go and try to restore with the original C program
