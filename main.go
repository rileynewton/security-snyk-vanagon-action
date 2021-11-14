package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
)

var LOCKFILE_DIR string = "gen_lockfile"
var DIR_MUTEX = &sync.Mutex{}

var MAX_V_DEPS = 20

func getEnvVar() (*config, error) {
	conf := config{}
	// token, org, and workspace are all required
	token := os.Getenv("INPUT_SNYKTOKEN")
	if token == "" {
		return nil, errors.New("no snyk token set")
	}
	conf.SnykToken = token
	org := os.Getenv("INPUT_SNYKORG")
	if org == "" {
		return nil, errors.New("no snyk org set")
	}
	conf.SnykOrg = org
	workspace := os.Getenv("GITHUB_WORKSPACE")
	if workspace == "" {
		return nil, errors.New("no github workspace set")
	}
	conf.GithubWorkspace = workspace
	// get noMonitor
	nomon := os.Getenv("INPUT_NOMONITOR")
	conf.NoMonitor = nomon != ""
	// skip projects and platforms are not, don't fail on it
	// platforms
	skipp := os.Getenv("INPUT_SKIPPROJECTS")
	if skipp != "" {
		splitstring := strings.Split(skipp, ",")
		for i := range splitstring {
			splitstring[i] = strings.TrimSpace(splitstring[i])
		}
		conf.SkipProjects = splitstring
	} else {
		conf.SkipProjects = []string{}
	}
	//projects
	skipr := os.Getenv("INPUT_SKIPPROJECTS")
	if skipr != "" {
		splitstring := strings.Split(skipr, ",")
		for i := range splitstring {
			splitstring[i] = strings.TrimSpace(splitstring[i])
		}
		conf.SkipProjects = splitstring
	} else {
		conf.SkipProjects = []string{}
	}
	// get the urls to replace if any
	urls := os.Getenv("INPUT_URLSTOREPLACE")
	if urls != "" {
		urlInput := strings.Split(urls, ",")
		for i := range urlInput {
			urlInput[i] = strings.TrimSpace(urlInput[i])
		}
		conf.UrlsToReplace = make(map[string]string)
		for i := 0; i < len(urlInput); i += 2 {
			conf.UrlsToReplace[urlInput[i]] = urlInput[i+1]
		}
	}
	// get the proxy host
	newhost := os.Getenv("INPUT_NEWHOST")
	if newhost != "" {
		conf.ProxyHost = newhost
	} else {
		conf.ProxyHost = ""
	}
	// return
	return &conf, nil
}

func vulnExists(totalVulns []VulnReport, vuln VulnReport) bool {
	for _, v := range totalVulns {
		if v.PackageName == vuln.PackageName && v.Version == vuln.Version {
			return true
		}
	}
	return false
}

func authSnyk(token string) error {
	err := exec.Command("snyk", "auth", token).Run()
	if err != nil {
		return err
	}
	return nil
}

// buildGemFile builds a gemfile and a gemfile.lock
func buildGemFile(project, platform string, gems *[]gem) (string, error) {
	// build the gemfile
	gemfile := "source ENV['GEM_SOURCE'] || \"https://rubygems.org\"\n"
	for _, gem := range *gems {
		gemfile += fmt.Sprintf("gem \"%s\", \"%s\"\n", gem.Name, gem.Version)
	}
	// make sure the output dir exists (creating if it doesn't) then write to a lockfile
	DIR_MUTEX.Lock()
	defer DIR_MUTEX.Unlock()
	err := os.MkdirAll(LOCKFILE_DIR, os.ModePerm)
	if err != nil {
		log.Println("couldn't create LOCKFILE_DIR", err)
		return "", err
	}
	oFolder := fmt.Sprintf("%s_%s", project, platform)
	lOutpath := filepath.Join(LOCKFILE_DIR, oFolder)
	err = os.MkdirAll(lOutpath, os.ModePerm)
	if err != nil {
		log.Printf("couldn't create lockfile output path on %s %s. %s", project, platform, err)
		return "", err
	}
	// write the gemfile to the output dir
	fPath := filepath.Join(LOCKFILE_DIR, oFolder, "Gemfile")
	err = os.WriteFile(fPath, []byte(gemfile), 0644)
	if err != nil {
		log.Println("couldn't write gemfile!", err)
		return "", err
	}
	//log.Printf("wrote Gemfile for %s %s", project, platform)
	cdir, err := os.Getwd()
	defer os.Chdir(cdir)
	if err != nil {
		log.Println("Couldn't get cdir!", err)
		return "", err
	}
	err = os.Chdir(lOutpath)
	if err != nil {
		log.Println("couldn't change to gemfile path", err)
		return "", err
	}
	err = exec.Command("bundle", "lock").Run()
	if err != nil {
		log.Println("Error generating lockfile from gemfile", err)
		return "", err
	}
	err = os.Chdir(cdir)
	if err != nil {
		log.Println("Error changing back to previous directory", err)
		return "", err
	}
	return lOutpath, nil
}

func processProjPlat(deps depsOut, org string, results chan processOut) {
	// if there are gems, write a gemfile and run snyk
	if len(*deps.Gems) > 0 {
		path, err := buildGemFile(deps.Project, deps.Platform, deps.Gems)
		if err != nil {
			log.Printf("error writing gemfile on: %s %s. Error: %s", deps.Project, deps.Platform, err)
			results <- processOut{}
			return
		}
		results <- processOut{
			hasGems:  true,
			project:  deps.Project,
			platform: deps.Platform,
			path:     path,
		}
	} else {
		log.Printf("no gems on %s %s", deps.Project, deps.Platform)
	}
	results <- processOut{hasGems: false}
}

func runSnyk(p processOut, org string, sem chan int, results chan []VulnReport, noMonitor bool) {
	log.Printf("running snyk on %s %s", p.project, p.platform)
	if !p.hasGems {
		<-sem
		results <- []VulnReport{}
		return
	}
	// TODO: change true -> false by default
	vulns, err := snykTest(p.path, p.project, p.platform, org, noMonitor)
	//<-sem
	if err != nil {
		log.Printf("error running snyk on: %s %s", p.project, p.platform)
		<-sem
		results <- []VulnReport{}
		return
	}
	<-sem
	results <- vulns
	log.Printf("Finished running snyk on %s %s", p.project, p.platform)
}

func snykTest(path, project, platform, org string, noMonitor bool) ([]VulnReport, error) {
	gPath := filepath.Join(path, "Gemfile.lock")
	cwd, _ := os.Getwd()
	fileArg := fmt.Sprintf("--file=%s/%s", cwd, gPath)
	log.Println("testing ", project, platform)
	// run snyk monitor
	if !noMonitor {
		snykOrg := fmt.Sprintf("--org=%s", org)
		snykProj := fmt.Sprintf("--project-name=%s_%s", project, platform)
		err := exec.Command("snyk", "monitor", snykOrg, snykProj, fileArg).Run()
		if err != nil {
			log.Println("error running snyk monitor!", err)
			return nil, err
		}
	}
	// run snyk test (note, this will throw a non-zero exit code on vulns being found)
	stest := exec.Command("snyk", "test", "--severity-threshold=medium", "--json", fileArg)
	t, _ := os.Getwd()
	_ = t
	var out bytes.Buffer
	var stderr bytes.Buffer
	stest.Stdout = &out
	stest.Stderr = &stderr
	err := stest.Run()
	if err != nil {
		// fail if it's anything but status 1 or 2
		if err.Error() != "exit status 1" {
			log.Println("error running snyk test.", err, out.String(), stderr.String())
			return nil, err
		}
	}
	log.Println("finished snyk testing: ", project, platform)
	sout := out.String()
	// get the vulns
	// fmt.Println(sout)
	vulns := gjson.Get(sout, "vulnerabilities").Array()
	oVulns := []VulnReport{}
	for _, vuln := range vulns {
		v := NewVulnReport(vuln)
		oVulns = append(oVulns, v)
	}
	// TODO: get the license issues
	//log.Println("finished snyk testing: ", fileArg)
	return oVulns, nil
}

func replaceUrls(path, newHost string, umap map[string]string) error {
	for url, nfmt := range umap {
		err := filepath.Walk(path, func(spath string, info os.FileInfo, err error) error {
			if info == nil {
				log.Fatal("Fatal: os.FileInfo is nil!")
			}
			// if it's a file
			if !info.IsDir() {
				// read the file to a string
				dat, err := os.ReadFile(spath)
				if err != nil {
					log.Printf("Error reading %s", spath)
					return nil
				}
				fstring := string(dat)
				// find and replace each URL (http and https replacement)
				hstring := fmt.Sprintf("http://%s", url)
				sstring := fmt.Sprintf("https://%s", url)
				// format the new host, then format according to the specifier
				newUrl := ""
				if newHost == "localhost" {
					newUrl = fmt.Sprintf("http://%s", newHost)
				} else {
					newUrl = fmt.Sprintf("https://%s", newHost)
				}
				newUrl = fmt.Sprintf(nfmt, newUrl)
				fstring = strings.Replace(fstring, hstring, newUrl, 1)
				fstring = strings.Replace(fstring, sstring, newUrl, 1)
				fstring = strings.Replace(fstring, "git://", "https://", -1)
				// rewrite the file
				err = os.WriteFile(spath, []byte(fstring), 0644)
				if err != nil {
					log.Printf("Error writing replacement %s", spath)
					return nil
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func setDebugEnvVars() {
	testrepo := "/Users/jeremy.mill/Documents/bolt-vanagon/"
	//testrepo := "/Users/jeremy.mill/Documents/puppet-runtime/"
	out, err := exec.Command("rm", "-rf", "./testfiles/repo").Output()
	if err != nil {
		log.Fatal("**DEBUG** failed to delete dir", err, out)
	}
	out, err = exec.Command("mkdir", "./testfiles/repo").Output()
	if err != nil {
		log.Fatal("**DEBUG** failed to copy dir", err)
	}
	_ = out
	out, err = exec.Command("cp", "-r", testrepo, "./testfiles/repo").Output()
	if err != nil {
		log.Fatal("**DEBUG** failed to copy dir", err)
	}
	_ = out
	os.Setenv("INPUT_SNYKTOKEN", os.Getenv("SNYK_TOKEN"))
	os.Setenv("INPUT_RPROXYKEY", os.Getenv("RPROXY_KEY"))
	//os.Setenv("INPUT_RPROXYKEY", "test")
	os.Setenv("INPUT_SNYKORG", "sectest")
	os.Setenv("INPUT_SKIPPROJECTS", "agent-runtime-5.5.x,agent-runtime-1.10.x,client-tools-runtime-irving,pdk-runtime")
	os.Setenv("INPUT_SKIPPLATFORMS", "cisco-wrlinux-5-x86_64,cisco-wrlinux-7-x86_64,debian-10-armhf,eos-4-i386,fedora-30-x86_64,fedora-31-x86_64,osx-10.14-x86_64")
	os.Setenv("GITHUB_WORKSPACE", "./testfiles/repo")
}

func main() {
	//setDebugEnvVars()
	conf, err := getEnvVar()
	if err != nil {
		log.Fatal("couldn't setup the env vars", err)
	}
	// change to the working directory
	os.Chdir(conf.GithubWorkspace)
	// auth snyk
	err = authSnyk(conf.SnykToken)
	if err != nil {
		log.Fatal("couldn't auth snyk!")
	}
	// get the projects and platforms
	projects, platforms := getProjPlats(conf)
	// replace the urls
	log.Println("replacing URLs")
	if len(conf.UrlsToReplace) > 0 {
		err = replaceUrls("./configs", conf.ProxyHost, conf.UrlsToReplace)
		if err != nil {
			log.Panic("error replacing URLs", err)
		}
	}
	// get all the vanagon dependencies
	log.Println("running vanagon deps")
	vDeps := runVanagonDeps(projects, platforms)
	// build gemfiles and run snyk on it
	log.Println("building gemfiles")
	// results := make(chan processOut, len(vDeps))
	results := make(chan processOut)
	toProcess := 0
	for _, dep := range vDeps {
		log.Printf("going to process %s %s", dep.Project, dep.Platform)
		toProcess += 1
		go processProjPlat(dep, conf.SnykOrg, results)
	}
	// collect all the processOuts
	p := []processOut{}
	for i := 0; i < toProcess; i++ {
		po := <-results
		if po.hasGems {
			p = append(p, po)
		}
	}
	// foreach processOut run snyk
	sem := make(chan int, MAX_V_DEPS)
	sresults := make(chan []VulnReport)
	totalVulns := []VulnReport{}
	toProcess = 0
	DIR_MUTEX.Lock()
	for _, po := range p {
		toProcess = toProcess + 1
		sem <- 1
		go runSnyk(po, conf.SnykOrg, sem, sresults, conf.NoMonitor)
	}
	for i := 0; i < toProcess; i++ {
		result := <-sresults
		for _, v := range result {
			if !vulnExists(totalVulns, v) {
				totalVulns = append(totalVulns, v)
			}
		}
	}

	if len(totalVulns) > 0 {
		// print the output and exit with status 1
		outString := totalVulns[0].String()
		for _, v := range totalVulns[1:] {
			outString += fmt.Sprintf("%s,", v.String())
		}
		outString = strings.TrimSuffix(outString, ",")
		fmt.Printf("::set-output name=vulns::%s\n", outString)
		os.Exit(0)
	} else {
		fmt.Print("::set-output name=vulns:: ")
		os.Exit(0)
	}
}
