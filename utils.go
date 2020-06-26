package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/hillu/go-yara"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Consts
const awesomeListURL = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"

func updateAwesomelist() {
	resp, err := http.Get(awesomeListURL)
	db := openDB()
	defer db.Close()
	if err != nil {
		log.Fatalln(err)
		db := openDB()
		defer db.Close()
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
				Description := scanner.Text()
				ruleset := Ruleset{Name: match[1], URL: match[2], Description: Description}
				// Create or update ruleset in db
				db.Where(Ruleset{Name: ruleset.Name}).Assign(ruleset).FirstOrCreate(&ruleset)
				rulesets = append(rulesets, ruleset)
			}
		}
	}

	resp.Body.Close()

	fmt.Printf("Downloading %d rulesets...\n", len(rulesets))
}

// Exists returns whether a given path exists
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Warning prints a warning if there is a non fatal error
func Warning(err error) {
	if err != nil {
		log.Printf("WARNING: %s", err)
	}
}

func printMatches(m []yara.MatchRule, err error) {
	if err == nil {
		if len(m) > 0 {
			for _, match := range m {
				log.Printf("- [%s] %s ", match.Namespace, match.Rule)
			}
		} else {
			log.Print("no matches.")
		}
	} else {
		log.Printf("error: %s.", err)
	}
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
		"\tadd - add a custom ruleset, located at <path>\n"+
		"\tscan - perform a yara scan on the directory at <path>\n")
	os.Exit(1)
}

func openDB() *gorm.DB {
	db, err := gorm.Open("sqlite3", dbPath)
	//db.LogMode(true)
	if err != nil {
		panic("failed to connect database")
	}
	return db
}

func printRulesets(rulesets []Ruleset) {
	fmt.Printf("%8s %s\t%45.45s\t%.45s\n", "Enabled", "ID", "Name", "Description")
	for _, ruleset := range rulesets {
		fmt.Printf("%8s %d\t%45.45s\t%.45s\n", ruleset.getStatus(), ruleset.ID, ruleset.Name, ruleset.Description)
	}
}
