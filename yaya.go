// YAYA: Yet Another Yara Automaton
// Automatically curate open source yara rules and run scans
// Author: Cooper Quintin - @cooperq - cooperq@eff.org

package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git"
	"github.com/hillu/go-yara"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// Ruleset is a record for a yara ruleset
type Ruleset struct {
	gorm.Model
	Name        string `gorm:"unique_index"`
	URL         string
	Description string
	Enabled     bool `gorm:"default:true"`
	Rules       []Rule
}

// Rule is an individual YARA rule
type Rule struct {
	gorm.Model
	Namespace string
	Path      string
	Enabled   bool `gorm:"default:true"`
	RulesetID uint
}

var rulesets []Ruleset
var rules []Rule

// Paths
var home, _ = os.UserHomeDir()
var configdir = path.Join(home, ".yaya")
var rulesetsdir = path.Join(configdir, "rulsets")

// Database
var dbPath = path.Join(configdir, "yaya.db")

func main() {
	if !(len(os.Args) >= 2) || os.Args[1] == "-h" {
		usage()
	}

	db := openDB()
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&Rule{})
	db.AutoMigrate(&Ruleset{})

	command := os.Args[1]
	var path string = ""
	if len(os.Args) > 2 {
		path = os.Args[2]
	}

	initYaya(db)

	switch command {
	case "update":
		updateRules()
	case "edit":
		editRules()
	case "add":
		if path == "" {
			log.Fatalln("You must specifcy a ruleset path or github url to add.")
		}
		addRules(path)
	case "scan":
		if path == "" {
			log.Fatalln("You must specifcy a path to scan.")
		}
		runScan(path)
	default:
		fmt.Println("Command not recognized")
		usage()
	}
}

//initYara populates the ruleset database with repos from the awesomelist
func initYaya(db *gorm.DB) {
	var count int
	db.Table("rulesets").Count(&count)
	if count > 1 {
		return
	}
	fmt.Println("Running YAYA for the first time. Gathering initial rulesets.")
	updateAwesomelist()
	updateRules()
}

// updateRules checks git repostitories for any new rules that have been added
func updateRules() {
	fmt.Println("Updating YARA Rules...")
	pullRulesets()
	findRules()
}

func loadRulesets(rulesets *[]Ruleset) {
	db := openDB()
	defer db.Close()

	db.Where("enabled = ?", true).Find(&rulesets)
}

func pullRulesets() {
	loadRulesets(&rulesets)
	for _, ruleset := range rulesets {
		rulesetPath := path.Join(rulesetsdir, ruleset.Name)
		pathExists, _ := Exists(rulesetPath)
		if !pathExists {
			fmt.Printf("git clone %q\n", ruleset.URL)

			_, err := git.PlainClone(rulesetPath, false, &git.CloneOptions{
				URL: ruleset.URL,
			})
			if err != nil {
				log.Println(err)
			}
		} else {
			fmt.Printf("git pull %s", ruleset.Name)
			// We instantiate a new repository targeting the given path (the .git folder)
			r, err := git.PlainOpen(rulesetPath)
			Warning(err)

			// Get the working directory for the repository
			w, err := r.Worktree()
			Warning(err)

			// Pull the latest changes from the origin remote and merge into the current branch
			err = w.Pull(&git.PullOptions{RemoteName: "origin"})
			Warning(err)
		}
	}
}

func findRules() {
	db := openDB()
	defer db.Close()
	loadRulesets(&rulesets)
	for _, ruleset := range rulesets {
		rulesetPath := path.Join(rulesetsdir, ruleset.Name)
		pathExists, _ := Exists(rulesetPath)
		if !ruleset.Enabled {
			continue
		}
		fmt.Printf("scanning %q located at %s\n", ruleset.Name, rulesetPath)
		if !pathExists {
			Warning(fmt.Errorf("the ruleset path %s doesn't exist, try running an update", rulesetPath))
			continue
		}

		// scan ruleset path for *.yar[a]?$
		filepath.Walk(rulesetPath, func(path string, info os.FileInfo, e error) error {
			if e != nil {
				return e
			}

			// check if it is a regular file (not dir)
			if info.Mode().IsRegular() {
				matched, _ := filepath.Match(`*.yar*`, info.Name())
				if matched {
					// create struct Rule and append to ruleset
					r := Rule{Path: path, RulesetID: ruleset.ID}
					record := db.FirstOrCreate(&r, r)
					rulename := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
					r.Namespace = fmt.Sprintf("%s:%s-%d", ruleset.Name, rulename, r.ID)
					db.Save(&r)
					// validate yara rule
					if r.Enabled {
						c, _ := yara.NewCompiler()
						f, err := os.Open(r.Path)
						if err != nil {
							log.Printf("Could not open rule file %s: %s\n", r.Path, err)
							return nil
						}
						err = c.AddFile(f, r.Namespace)
						f.Close()
						if err != nil {
							log.Printf("Could not parse rule file %s: %s", r.Path, err)
							r.Enabled = false
							db.Save(&r)
						}
					}

					db.Model(&ruleset).Association("Rules").Append(record)
				}
			}
			return nil
		})
		// DB update ruleset
		db.Save(&ruleset)
	}
}

// editRules presents a UI allowing the user to ban certain rulesets or individual rules
func editRules() {
	loadRulesets(&rulesets)
	fmt.Println("Editing YARA Rules.")
}

// addRules allows the user to add a ruleset from either a git repository or local file path
func addRules(path string) {
	fmt.Println("Adding YARA Rules from ", path)
}

// runScan Scan a path recursively with every rule in the database
func runScan(path string) {
	loadRulesets(&rulesets)
	db := openDB()
	defer db.Close()

	//db.Where("enabled = ?", true).Find(&rulesets)
	for _, ruleset := range rulesets {
		c, err := yara.NewCompiler()
		if err != nil {
			log.Fatalf("Failed to initialize YARA compiler: %s", err)
		}
		db.Where("enabled = ?", true).Model(&ruleset).Related(&rules)
		fmt.Printf("Ruleset %s scanning with %d rules\n", ruleset.Name, len(rules))
		for _, rule := range rules {
			f, err := os.Open(rule.Path)
			if err != nil {
				log.Printf("Could not open rule file %s: %s\n", rule.Path, err)
			}
			err = c.AddFile(f, rule.Namespace)
			f.Close()
			if err != nil {
				log.Printf("Could not parse rule file %s: %s", rule.Path, err)
				break
			}
		}
		rules, err := c.GetRules()
		if err != nil {
			log.Printf("Failed to compile rules: %s", err)
			continue
		}

		var matches yara.MatchRules

		log.Printf("Scanning file %s... ", path)
		matches, err = rules.ScanFile(path, 0, 0)
		printMatches(matches, err)
		//fmt.Printf("Rules: %q\n\nMatches: %q", rules, matches)
		/*
			for _, filename := range args {
				log.Printf("Scanning file %s... ", path)
				err := rules.ScanFile(path, 0, 0, &m)
				printMatches(m, err)
			}
		*/
	}
}
