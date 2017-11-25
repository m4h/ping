## About

An miserable attempt to implement basic ping functionality and extend it with more features.
Written solely for educational purposes and not for production use. Probably contain many bugs and horrible code style :-)
You are welcome to report them or just leave some feedback.


## Use cases

ping forever until it crashes due to some bug :-)
```
./ping google-public-dns-a.google.com. -c -1
--- ping google-public-dns-a.google.com. (8.8.8.8) ttl=32; count=-1; timeout=5s ---
src=8.8.8.8 rtt=73.95ms ttl=51 seq=1 type=echoreply code=null
...
```

set packet TTL to find next hop (router) address (this is how tracert|traceroute|tracepath|mtr works)
```
./ping google-public-dns-a.google.com. -T 1 -c 3
--- ping google-public-dns-a.google.com. (8.8.8.8) ttl=1; count=3; timeout=5s ---
src=10.1.0.1 rtt=3.48ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
src=10.1.0.1 rtt=3.47ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
src=10.1.0.1 rtt=3.51ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
--- ping google-public-dns-a.google.com. (8.8.8.8) statistics ---
min rtt=3.47ms; max rtt=3.51ms; avg rtt=3.49ms; sent=3; recv=3; lost=0
```

## Links

[how traceroute works](https://security.stackexchange.com/questions/39178/how-does-traceroute-over-tcp-work-what-are-the-risks-and-how-can-it-be-mitig)
