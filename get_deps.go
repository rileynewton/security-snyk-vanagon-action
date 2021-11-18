package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
)

func getProjPlats(conf *config) ([]string, []string) {
	projects, err := getRbFiles("./configs/projects", &conf.SkipProjects)
	if err != nil {
		log.Fatal("couldn't get projects", err)
	}
	platforms, err := getRbFiles("./configs/platforms", &conf.SkipPlatforms)
	if err != nil {
		log.Fatal("couldn't get folders")
	}
	return projects, platforms
}

func getRbFiles(path string, skip *[]string) ([]string, error) {
	var pSlice []string
	err := filepath.Walk(path, func(spath string, info os.FileInfo, err error) error {
		// make sure it's a ruby file and it doesn't start with an underscore
		filename := filepath.Base(spath)
		if strings.HasSuffix(filename, ".rb") && !strings.HasPrefix(filename, "_") {
			pname := strings.Replace(filename, ".rb", "", -1)
			if !inSkip(skip, pname) {
				pSlice = append(pSlice, pname)
			}
		}
		return nil
	})
	if err != nil {
		return []string{}, err
	}
	return pSlice, nil
}

func inSkip(skip *[]string, pname string) bool {
	// this function isn't very efficient, but it's also not called very often
	for _, v := range *skip {
		if pname == v {
			return true
		}
	}
	return false
}

func runVanagonDeps(projects, platforms []string, debug bool) []depsOut {
	ppGems := []depsOut{}
	results := make(chan depsOut)
	sem := make(chan int, MAX_V_DEPS)
	toProcess := 0
	total := len(projects) * len(platforms)
	for _, project := range projects {
		for _, platform := range platforms {
			sem <- 1
			toProcess += 1
			log.Printf("getting vdeps for %s %s. %d/%d", project, platform, toProcess, total)
			go getVanagonGems(project, platform, results, sem, debug)
		}
	}
	for i := 0; i < toProcess; i++ {
		result := <-results
		ppGems = append(ppGems, result)
		log.Printf("done getting vdeps for %s %s", result.Project, result.Platform)
	}
	return ppGems
}

func getVanagonGems(project, platform string, result chan depsOut, sem chan int, debug bool) {
	do := depsOut{
		Platform: platform,
		Project:  project,
	}
	// log.Printf("in get deps: %s %s", project, platform)
	var findex int
	var lindex int
	var output []byte
	for try := 0; try < 3; try++ {
		vcmd := exec.Command("vanagon", "dependencies", project, platform)
		var cout bytes.Buffer
		var stderr bytes.Buffer
		vcmd.Stdout = &cout
		vcmd.Stderr = &stderr
		err := vcmd.Run()
		log.Printf("finished vanagon deps run for %s %s", project, platform)
		if err != nil {
			log.Printf("Error running vanagon dependencies on: %s %s. Try #%d. Err: %s", project, platform, try, err)
			if debug {
				log.Printf("===DEBUG===\n%s\n===DEBUG===\n", stderr.String())
			}
			log.Println(string(output))
		}
		// strip out the any other data in stdout
		findex = strings.Index(cout.String(), "{")
		lindex = strings.LastIndex(cout.String(), "}")
		if findex == -1 || lindex == -1 {
			log.Printf("Got bad output from vanagon dependencies on %s %s. Try #%d Output: %s", project, platform, try, cout.String())
		} else {
			output = cout.Bytes()
			break
		}
	}
	<-sem
	if output == nil {
		log.Printf("Total failure to run vanagon on %s %s", project, platform)
		gems := make([]gem, 0)
		do := depsOut{Gems: &gems}
		result <- do
		return
	}
	trimString := string(output)[findex : lindex+1]
	components := gjson.Get(trimString, "components").Map()
	gems := make([]gem, 0)
	for name, component := range components {
		version := gjson.Get(component.Raw, "version").String()
		url := gjson.Get(component.Raw, "url").String()
		// skip non gems
		if !strings.HasSuffix(url, ".gem") {
			continue
		}
		// check for blanks
		if version == "" || url == "" {
			log.Printf("blank version or url in component: %s on: %s %s", name, project, platform)
			continue
		}
		if strings.HasPrefix(url, "https://rubygems.org") || strings.HasPrefix(url, "http://rubygems.org") {
			gem, err := getGemFromURL(url)
			if err != nil {
				log.Println("error getting gem from url", err)
				continue
			}
			gems = append(gems, gem)
		}
	}
	do.Gems = &gems
	result <- do

}

func getGemFromURL(url string) (gem, error) {
	// trim the URL to the final part of the path and replace .gem with ""
	splitString := strings.Split(url, "/")
	nameAndVer := splitString[len(splitString)-1]
	nameAndVer = strings.Replace(nameAndVer, ".gem", "", -1)
	// find the last index of "-" and split on it, rhs is the verion, lhs
	// is the gem name
	lastIndex := strings.LastIndex(nameAndVer, "-")
	name := nameAndVer[:lastIndex]
	version := nameAndVer[lastIndex+1:]
	return gem{Name: name, Version: version}, nil
}
