!["Bender from futurama dressed up like the Terminator"](https://i.pinimg.com/originals/04/e3/cf/04e3cf941acd1d64eb42aa3cced37d11.jpg "YAYA - Yet Another Yara Automaton")

# YAYA - *Yet Another Yara Automaton*

Automatically curate open source yara rules and run scans

## Installation
`go get github.com/cooperq/yaya`

`go install github.com/cooperq/yaya`

### Dependencies 
Yaya depends on the following packages outside the standard library:
* https://github.com/go-git/go-git
* https://github.com/hillu/go-yara
* https://github.com/jinzhu/gorm

You must also install the yara4 C libraries. We reccomend you install these from source: 
https://yara.readthedocs.io/en/stable/gettingstarted.html


## Running
    yaya update
    yaya add https://github.com/example/exampleYaraRules.git
    yaya scan /path/to/scan

## Usage
```
yaya [-h] <command> <path>
	-h	 print this help screen
Commands:
	update - update rulesets
	edit - ban or remove rulesets
	add - add a custom ruleset, located at <path>
	scan - perform a yara scan on the directory at <path>
```