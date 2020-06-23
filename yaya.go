// YAYA: Yet Another Yara Automaton
// Automatically curate open source yara rules and run scans
// Author: Cooper Quintin - @cooperq - cooperq@eff.org

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"

	"github.com/go-git/go-git"
)

// Ruleset is a record for a yara ruleset
type Ruleset struct {
	name        string
	url         string
	description string
	enabled     bool
}

var rulesets []Ruleset
var home, _ = os.UserHomeDir()
var configdir = path.Join(home, ".yaya")
var rulesetsdir = path.Join(configdir, "rulsets")

func updateAwesomelist() {
	var awesomeListURL = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"
	resp, err := http.Get(awesomeListURL)
	if err != nil {
		log.Fatalln(err)
	}
	if resp.Status != "200 OK" {
		//body, _ := ioutil.ReadAll(resp.Body)
		//fmt.Println(string(body))

		log.Fatalln(resp.Status, "Could not fetch awesome yara")
	}

	scanner := bufio.NewScanner(resp.Body)
	flag := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "## Rules" {
			flag = true
		} else if line == "## Tools" {
			break
		} else {
			if flag {
				re := regexp.MustCompile(`\[(.*)\]\((https://github.*)\)`)
				match := re.FindStringSubmatch(line)
				if len(match) < 3 {
					// Not a successfull match so lets continue to the next line
					continue
				}

				scanner.Scan()
				description := scanner.Text()
				r := Ruleset{match[1], match[2], description, true}
				rulesets = append(rulesets, r)
			}
		}
	}

	resp.Body.Close()

	fmt.Printf("Downloading %q rulesets...\n", len(rulesets))
}

func cloneRulesets() {
	for _, ruleset := range rulesets {
		fmt.Printf("git clone %q\n", ruleset.url)

		_, err := git.PlainClone(path.Join(rulesetsdir, ruleset.name), false, &git.CloneOptions{
			URL: ruleset.url,
		})
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

// updateRules checks git repostitories for any new rules that have been added
func updateRules() {
	fmt.Println("Updating YARA Rules...")
	updateAwesomelist()
	cloneRulesets()
}

// editRules presents a UI allowing the user to ban certain rulesets or individual rules
func editRules() {
	fmt.Println("Editing YARA Rules...")
}

// addRules allows the user to add a ruleset from either a git repository or local file path
func addRules(path string) {
	fmt.Println("Adding YARA Rules from ", path)
}

// scan Scan a path recursively with every rule in the database
func scan(path string) {
	fmt.Println("Scanning at ", path)
}

// usage prints help about the program
func usage() {
	fmt.Print(""+
		"YAYA - Yet Another Yara Automaton\n"+
		"Usage:\n"+
		os.Args[0], " [-h] <command> <path>\n"+
		"\t-h\t print this help screen\n"+
		"Commands:\n"+
		"\tupdate - update rulesets\n"+
		"\tedit - ban or remove rulesets\n"+
		"\tadd - add a custom ruleset\n"+
		"\tscan - perform a yara scan\n")
	os.Exit(1)
}

func main() {
	if !(len(os.Args) >= 2) || os.Args[1] == "-h" {
		usage()
	}

	command := os.Args[1]
	var path string
	if len(os.Args) > 2 {
		path = os.Args[2]
	}

	switch command {
	case "update":
		updateRules()
	case "edit":
		editRules()
	case "add":
		addRules(path)
	case "scan":
		scan(path)
	default:
		fmt.Println("Command not recognized")
		usage()
	}
}
