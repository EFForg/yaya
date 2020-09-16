package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/hillu/go-yara"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Consts
const awesomeListURL = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"

// installDefaultRules clones the rulesets listed in defaultRulesets
func installDefaultRules() {
	db := openDB()
	defer db.Close()

	for _, ruleset := range defaultRulesets {
		// Create or update ruleset in db
		db.Where(Ruleset{Name: ruleset.Name}).Assign(ruleset).FirstOrCreate(&ruleset)
		rulesets = append(rulesets, ruleset)
	}
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

// printMatches prints match results to the screen in a human readable way
func printMatches(results map[string][]yara.MatchRule) {
	for filePath, matches := range results {
		log.Printf("%s:", filePath)
		if len(matches) > 0 {
			for _, match := range matches {
				log.Printf("  - [%s] %s ", match.Namespace, match.Rule)
			}
		} else {
			log.Print("  - no matches.")
		}
	}
}

// saveMatchesJSON saves match results to json file for later processing
func saveMatchesJSON(results map[string][]yara.MatchRule) {
	outpath := "/tmp/yaya.json"

	txt, err := json.Marshal(results)
	if err != nil {
		log.Panicf("Marshaling error: %s", err)
	}

	f, err := os.Create(outpath)
	defer f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	f.Write(txt)
	log.Printf("json output written to %s", outpath)
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
