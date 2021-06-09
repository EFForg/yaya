!["The YAYA logo and automaton mascot"](https://www.eff.org/files/banner_library/yaya_yaya_banner.png "YAYA - Yet Another Yara Automaton")

# YAYA - *Yet Another Yara Automaton*

Automatically curate open source yara rules and run scans

## Installation
```
go get github.com/EFForg/yaya
cd $GOPATH/src/github.com/EFForg/yaya
go build 
go install 
```
### Dependencies 
Yaya depends on the following packages outside the standard library:
* https://github.com/go-git/go-git
* https://github.com/hillu/go-yara
* https://github.com/jinzhu/gorm

You must also install the yara4 C libraries. We recommend you install these from source with the following command: 

```
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.0.tar.gz && mkdir yara && cd yara && tar xf ../v4.1.0.tar.gz \
    && cd yara-4.1.0/ && ./bootstrap.sh && ./configure --enable-cuckoo --enable-magic --enable-dotnet && make && sudo make install && sudo ldconfig
```
More info and docs can be [found here](https://yara.readthedocs.io/en/stable/gettingstarted.html)
## Running
[![asciicast](https://asciinema.org/a/344120.svg)](https://asciinema.org/a/344120)

## Usage
```
yaya [-h] <command> <path>
	-h	 print this help screen
Commands:
	update - update rulesets
	edit - ban or remove rulesets
	add - add a custom ruleset, located at <path>
	scan - perform a yara scan on the directory at <path>
	export - export all yara rules in single yar file in <path>
```
## Docker
YAYA includes a docker file and can be run inside a container as well by linking the path to be scanned to a path in the container. 
