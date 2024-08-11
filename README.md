# A simple tunnel

this is a simple tunnel using pre-shared keys for encryption. it tunnels both ipv4 and ipv6 packets into a ipv4 tunnel. this program uses the `ip` and `iptables` & `ip6tables` commands to manipulate ip addresses, routes and ip tables, so it requires the user to have corresponding capabilities, or simply run as root. this program uses the `crypto` lib for encryption.

### usage

start the server on a machine which could forward packets:

```bash
$ ./tun -g > tun.key
$ ./tun
```

copy `tun.key` to the local machine(the key is pre-shared, e.g. by some other secure means) start the client locally:

```bash
$ ./tun -s <server address>
```

now all ip packets should go through the tunnel.

### notes

this is a quick work, not very clean, but works well enough for my own use.
