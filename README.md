# dvpn-decrypter

SOLAR Labs dVPN app currently (07.06.2022) does not support mnemonic seed export. So I did some reverse engineering and wrote this small utility.
Devs from SOLAR Labs use Themis as crypto framework, it's not my idea to use it.

Read source code and compile it by yourself, I don't want you to think that I'm a scamer :)

## Usage
1. Install [themis](https://docs.cossacklabs.com/themis/installation/installation-from-packages/) (you will probably need Linux or Windows with WSL)
2. `go build dvpn-decrypter`
3. Launch it like this `./dvpn-decrypter -email "your@cool.email" -pass "your_cool_pass_from_solar_id"`

## Help
```bash
./dvpn-decrypter -h
Usage of ./dvpn-decrypter:
  -email string
        your email
  -pass string
        your password
```
