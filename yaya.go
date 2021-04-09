// YAYA: Yet Another Yara Automaton
// Automatically curate open source yara rules and run scans
// Author: Cooper Quintin - @cooperq - cooperq@eff.org

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"io/ioutil"

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

func (ruleset *Ruleset) toggleEnabled() {
	db := openDB()
	defer db.Close()
	ruleset.Enabled = !ruleset.Enabled
	db.Save(&ruleset)
}

func (ruleset *Ruleset) getStatus() string {
	var status string
	if ruleset.Enabled {
		status = "enabled"
	} else {
		status = "disabled"
	}
	return status
}

// Rule is an individual YARA rule
type Rule struct {
	gorm.Model
	Namespace string
	Path      string
	Enabled   bool `gorm:"default:true"`
	Ruleset   Ruleset
	RulesetID uint
}

func (rule *Rule) toggleEnabled() {
	db := openDB()
	defer db.Close()
	rule.Enabled = !rule.Enabled
	db.Save(&rule)
}

// Collections
var rulesets []Ruleset
var rules []Rule
var scanResults = map[string][]yara.MatchRule{}

// Paths
var home, _ = os.UserHomeDir()
var configPath = path.Join(home, ".yaya")
var rulesetsPath = path.Join(configPath, "rulsets")
var dbPath = path.Join(configPath, "yaya.db")

func main() {
	// Make config directories if they don't exist
	os.MkdirAll(rulesetsPath, os.ModePerm)

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
			log.Fatalln("You must specify a ruleset path or github url to add.")
		}
		addRuleset(path)
	case "scan":
		if path == "" {
			log.Fatalln("You must specify a path to scan.")
		}
		runScan(path)
	case "export":
		if path == "" {
			log.Fatalln("You must specify an output path.")
		}		
		exportRules(path)
	case "exportcompiled":
		if path == "" {
			log.Fatalln("You must specify an output path.")
		}		
		exportRulesCompiled(path)		
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
	installDefaultRules()
	updateRules()
	os.Exit(0)
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

func loadAllRulesets(rulesets *[]Ruleset) {
	db := openDB()
	defer db.Close()

	db.Find(&rulesets)
}

func pullRulesets() {
	loadRulesets(&rulesets)
	for _, ruleset := range rulesets {
		pullRuleset(&ruleset)
	}
}

func pullRuleset(ruleset *Ruleset) {
	rulesetPath := path.Join(rulesetsPath, ruleset.Name)
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

func findRules() {
	db := openDB()
	defer db.Close()
	loadRulesets(&rulesets)
	for _, ruleset := range rulesets {
		updateRulesetRules(&ruleset, db)
	}
}

func updateRulesetRules(ruleset *Ruleset, db *gorm.DB) {
	rulesetPath := path.Join(rulesetsPath, ruleset.Name)
	pathExists, _ := Exists(rulesetPath)
	if !ruleset.Enabled {
		return
	}
	fmt.Printf("loading %q located at %s\n", ruleset.Name, rulesetPath)
	if !pathExists {
		Warning(fmt.Errorf("the ruleset path %s doesn't exist, disabling for now", rulesetPath))
		ruleset.Enabled = false
		db.Save(&ruleset)
		return
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

// editRules presents a UI allowing the user to ban certain rulesets or individual rules
func editRules() {
	loadAllRulesets(&rulesets)
	printRulesets(rulesets)

	fmt.Print("Enter ruleset indexes (space seperated) to toggle: ")

	db := openDB()
	defer db.Close()
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSuffix(text, "\n")
	input := strings.Split(text, " ")
	for _, next := range input {
		var ruleset Ruleset
		idx, err := strconv.Atoi(next)
		if err != nil {
			log.Panicf("Couldn't parse input: %s", err)
		}
		if db.First(&ruleset, idx).Error != nil {
			fmt.Printf("Ruleset %d is not in the database\n", idx)
			continue
		}
		ruleset.toggleEnabled()
		fmt.Printf("Ruleset %d \"%s\" is now %s\n", ruleset.ID, ruleset.Name, ruleset.getStatus())
	}
	return
}

// addRuleset allows the user to add a ruleset from either a git repository or local file path
func addRuleset(path string) {
	db := openDB()
	defer db.Close()
	fmt.Println("Adding YARA Rules from ", path)
	match, _ := regexp.MatchString(`\.git$`, path)
	if !match {
		// Not a successfull match so lets continue to the next line
		log.Panicln("not a git repository")
	}

	s := strings.TrimSuffix(path, ".git")
	name := s[strings.LastIndex(s, "/")+1:]
	description := "Custom yara rules"
	ruleset := Ruleset{Name: name, URL: path, Description: description, Enabled: true}
	fmt.Printf("creating ruleset %+v\n", ruleset)
	// Create or update ruleset in db
	db.Create(&ruleset)
	pullRuleset(&ruleset)
	updateRulesetRules(&ruleset, db)
}

// runScan Scan a path recursively with every rule in the database
func runScan(scanPath string) {
	db := openDB()
	defer db.Close()

	filepath.Walk(scanPath, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}

		// check if it is a regular file (not dir)
		if info.Mode().IsRegular() {
			var m []yara.MatchRule
			scanResults[path] = m
		}
		return nil
	})

	db.Where("enabled = ?", true).Find(&rulesets)

	for _, ruleset := range rulesets {
		c, err := yara.NewCompiler()
		if err != nil {
			log.Fatalf("Failed to initialize YARA compiler: %s", err)
		}

		db.Model(&ruleset).Where("enabled = ?", true).Related(&rules)

		log.Printf("Scanning with %s. Compiling %d rules\n", ruleset.Name, len(rules))
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
			log.Panicf("Failed to compile rules: %s", err)
		}
		for path, matches := range scanResults {
			var results yara.MatchRules
			err := rules.ScanFile(path, 0, 0, &results)
			if err != nil {
				Warning(err)
			}
			scanResults[path] = append(matches, results...)
		}

	}
	printMatches(scanResults)
	saveMatchesJSON(scanResults)
}

// Export rules in plaintext instead of compiled
func exportRules(outputPath string) {
	db := openDB()
	defer db.Close()
	
	db.Where("enabled = ?", true).Find(&rulesets)

    outFile, err := os.Create(outputPath)
	if err != nil {
		log.Printf("Could not open rule file %s: %s\n", outputPath, err)
	}
	defer outFile.Close()
	
	for _, ruleset := range rulesets {
		db.Model(&ruleset).Where("enabled = ?", true).Related(&rules)
		for _, rule := range rules {
			dat, err := ioutil.ReadFile(rule.Path)
			if err != nil {
				log.Printf("Could not open rule file %s: %s\n", rule.Path, err)
				return
			}

			outFile.Write(dat)
			outFile.WriteString("\n")
			outFile.Sync()
		}
	}


}

func exportRulesCompiled(outputPath string) {
	db := openDB()
	defer db.Close()
	
	db.Where("enabled = ?", true).Find(&rulesets)
	
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}

	for _, ruleset := range rulesets {
		db.Model(&ruleset).Where("enabled = ?", true).Related(&rules)
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
	}
	mainRule, err := c.GetRules()
	if err != nil {
		log.Panicf("Failed to compile rules: %s", err)
	}
	mainRule.Save(outputPath)
}