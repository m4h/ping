## About

An miserable attempt to implement basic ping functionality and extend it with more features.
Written solely for educational purposes and not for production use. Probably contain many bugs and horrible code style :-)
You are welcome to report them or just leave some feedback.


## Use cases

ping forever until it crashes due to some bug :-)
```
./ping 8.8.8.8 -c -1
--- ping 8.8.8.8 (ttl=32 count=-1 timeout=5) ---
src=8.8.8.8 rtt=71.12ms ttl=58 seq=1 type=echoreply code=null
...
```

decrement TTL of a packet to find next hop (router) address (this is how tracert|traceroute|tracepath|mtr works)
```
./ping 8.8.8.8 -T 1
--- ping 8.8.8.8 (ttl=1 count=3 timeout=5) ---
src=10.0.0.138 rtt=3.48ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
src=10.0.0.138 rtt=3.46ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
src=10.0.0.138 rtt=3.55ms ttl=64 seq=0 type=time_exceeded code=exc_ttl
--- ping 8.8.8.8 statistics ---
min rtt=3.46ms; max rtt=3.55ms; avg rtt=3.50ms
```

## Links

[how traceroute works](https://security.stackexchange.com/questions/39178/how-does-traceroute-over-tcp-work-what-are-the-risks-and-how-can-it-be-mitig)
