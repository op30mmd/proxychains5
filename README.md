# proxychains5
Just a simple proxy chaining script, written in python with stdlibs

# how to use

Simple chain: local SOCKS5 on port 1080 → your proxy chain

```
python chains.py \
  --proxy http://proxy1.example.com:8080 \
  --proxy socks5://user:pass@proxy2.example.com:1080 \
  --proxy socks4://proxy3.example.com:1081 \
  --listen 127.0.0.1:1080
```
