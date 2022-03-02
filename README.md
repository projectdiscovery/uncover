<h1 align="center">
  uncover
  <br>
</h1>

<h4 align="center">Quickly discover exposed assets on the internet using multiple search engines.</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/uncover">
<a href="https://github.com/projectdiscovery/uncover/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/uncover/releases"><img src="https://img.shields.io/github/release/projectdiscovery/uncover"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-instructions">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#provider-configuration">Configuration</a> •
  <a href="#running-uncover">Running Uncover</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


---

**uncover** is a go wrapper using APIs of well known search engines to quickly discover exposed hosts on the internet. It is built with automation in mind, so you can query it and utilize the results with your current pipeline tools.

# Features

<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/156347215-a9ed00c2-4161-4773-9372-29fc32200f6a.png" alt="httpx" width="700px"></a>
  <br>
</h1>

- Simple and Handy utility to query multiple search engine
- Multiple Search engine support (**Shodan**, **Censys**, **Fofa**)
- Automatic key/credential randomization
- **stdin** / **stdout** support for input and output

# Installation Instructions

uncover requires **go1.17** to install successfully. Run the following command to get the repo -

```sh
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
```

# Usage

```sh
uncover -h
```

This will display help for the tool. Here are all the flags it supports:

```console
Usage:
  ./uncover [flags]

Flags:
INPUT:
   -q, -query string[]   search query or list (file or comma separated or stdin)
   -e, -engine string[]  search engine to query (shodan,fofa,censys) (default shodan)

CONFIG:
   -pc, -provider string  provider configuration file (default "$HOME/.config/uncover/provider-config.yaml")
   -config string         flag configuration file (default "$HOME/.config/uncover/config.yaml")
   -timeout int           timeout in seconds (default 10)

OUTPUT:
   -o, -output string  output file to write found results
   -f, -field string   field to display in output (ip,port,host) (default ip:port)
   -j, -json           write output in JSONL(ines) format
   -l, -limit int      limit the number of results to return (default 100)
   -nc, -no-color      disable colors in output

DEBUG:
   -silent   show only results in output
   -version  show version of the project
   -v        show verbose output
```

# Provider Configuration

The default provider configuration file should be located at `$HOME/.config/uncover/provider-config.yaml` and has the following contents as an example. **In order to run this tool, the API keys / credentials needs to be added in this config file or set as environment variable.**

```yaml
shodan:
  - SHODAN_API_KEY1
  - SHODAN_API_KEY2
censys:
  - CENSYS_API_ID:CENSYS_API_SECRET
fofa:
  - FOFA_EMAIL:FOFA_KEY
```

When multiple keys/credentials are specified for same provider in the config file, random key will be used for each execution.

alternatively you can also set the API key as environment variable in your bash profile.

```yaml
export SHODAN_API_KEY=xxx
export CENSYS_API_ID=xxx
export CENSYS_API_SECRET=xxx
export FOFA_EMAIL=xxx
export FOFA_KEY=xxx
```

Required keys can be obtained by signing up on [Shodan](https://account.shodan.io/register), [Censys](https://censys.io/register), [Fofa](https://fofa.info/toLogin).

## Running Uncover

**uncover** supports multiple ways to make the query including **stdin** or `q` flag, for example:-

```console
echo grafana | uncover 
                                        
  __  ______  _________ _   _____  _____
 / / / / __ \/ ___/ __ \ | / / _ \/ ___/
/ /_/ / / / / /__/ /_/ / |/ /  __/ /    
\__,_/_/ /_/\___/\____/|___/\___/_/ v0.0.1    
                                        

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[WRN] By using uncover, you also agree to the terms of the APIs used.

52.18.18.74:443
139.162.175.222:8081
2a02:20c8:2640::2:3000
34.90.119.170:80
222.209.83.170:3001
52.35.140.14:443
2607:7c80:54:3::74:3001
104.198.55.35:80
46.101.82.244:3000
34.147.126.112:80
138.197.147.213:8086
```

**uncover** supports `field` flag to print specific field in the output, currently `ip`, `port`, `host` fields are supported. for example:-

```console
uncover -q jira -f host -silent

ec2-44-198-22-253.compute-1.amazonaws.com
ec2-18-246-31-139.us-west-2.compute.amazonaws.com
tasks.devrtb.com
leased-line-91-149-128-229.telecom.by
74.242.203.213.static.inetbone.net
ec2-52-211-7-108.eu-west-1.compute.amazonaws.com
ec2-54-187-161-180.us-west-2.compute.amazonaws.com
185-2-52-226.static.nucleus.be
ec2-34-241-80-255.eu-west-1.compute.amazonaws.com
```


**uncover** supports `field` flag which can be also used to customize the format of the output, for example in case of  `uncover -f https://ip:port/version`, `ip:port` will be replaced with results in the output maintaining the defined format.

```console
echo kubernetes | uncover -f https://ip:port/version -silent

https://35.222.229.38:443/version
https://52.11.181.228:443/version
https://35.239.255.1:443/version
https://34.71.48.11:443/version
https://130.211.54.173:443/version
https://54.184.250.232:443/version
```

**uncover** supports multiple search engine, as default **shodan** is used, `engine` flag can be used to specify any available search engines. for example:-

```console
echo jira | uncover -e shodan,censys -silent

176.31.249.189:5001
13.211.116.80:443
43.130.1.221:631
192.195.70.29:443
52.27.22.181:443
117.48.120.226:8889
106.52.115.145:49153
13.69.135.128:443
193.35.99.158:443
18.202.109.218:8089
101.36.105.97:21379
42.194.226.30:2626
```

Output of **uncover** can be further piped to other projects in workflow accepting **stdin** as input, for example:-


- `uncover -q http.title:"GitLab" | httpx` - Runs [httpx](https://github.com/projectdiscovery/httpx) for web server probing the found result.
- `uncover -q example | httpx | nuclei` - Runs [httpx](https://github.com/projectdiscovery/httpx) / [nuclei](https://github.com/projectdiscovery/nuclei) for vulnerability assessment on found host.
- `uncover -q example -f ip | naabu` - Runs [naabu](https://github.com/projectdiscovery/naabu) for port scanning on the found host.


```console
uncover -q http.title:GeoWebServer -silent | httpx -silent

https://108.213.48.77
https://173.241.180.147
https://173.239.95.16
http://179.49.67.66
https://109.88.84.93
https://181.174.200.162
https://142.179.224.207
```

## Note

-  **keys/ credentials** are required to configure before running or using this project.
- `query` flag supports all the filters supported by underlying API in use.
- `query` flag input needs be compatible with search engine in use.
- results are limited to `100` as default and can be increased with `limit` flag.

-----

<div align="center">

**uncover** is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.

</div>
