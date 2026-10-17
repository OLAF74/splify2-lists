package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	retries    = 3
	retryDelay = 30 * time.Second
)

var (
	cnPattern    = regexp.MustCompile(`(?i)^cn$|^cn[-_]|[-_]cn$|[-_]cn[-_]|china|geolocation-cn`)
	cnDomainRE   = regexp.MustCompile(`(?i)\.(cn|hk|mo|tw)$`)
	atAnnotation = regexp.MustCompile(`:@(\S+)$`)
	labelRE      = regexp.MustCompile(`\\\.([a-zA-Z0-9][a-zA-Z0-9-]*)`)
	strictLabel  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)
	prefixRE     = regexp.MustCompile(`^(?:full:|domain:|regexp:|keyword:|ext:\S+:)`)
	regexChars   = regexp.MustCompile(`[\\^$+*?{}\[\]()|]`)
	cnSuffixRE   = regexp.MustCompile(`(?i)-!cn$`)
	excludedTags = map[string]struct{}{
		"category-ads-all":     {},
		"ru-blocked":           {},
		"ru-blocked-all":       {},
		"ru-blocked-community": {},
		"category-ads-ir":      {},
		"category-ads":         {},
		"adblock":              {},
		"adblockplus":          {},
		"ad":                   {},
		"antifilter-download":  {},
		"direct":               {},
		"geolocation":          {},
		"0":                    {},
		"0x0":                  {},
		"code":                 {},
		"reject":               {},
		"proxy":                {},
	}
	httpClient = &http.Client{Timeout: 300 * time.Second}
)

type strSet map[string]struct{}

func (s strSet) add(v string)      { s[v] = struct{}{} }
func (s strSet) has(v string) bool { _, ok := s[v]; return ok }
func (s strSet) sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (s strSet) ips() []string {
	out := make([]string, 0, 1)
	for k := range s {
		if isIPEntry(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
func (s strSet) domains() []string {
	out := make([]string, 0, 1)
	for k := range s {
		if !isIPEntry(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

type tagSet map[string]strSet

func (t tagSet) add(tag, entry string) {
	if t[tag] == nil {
		t[tag] = make(strSet)
	}
	t[tag].add(entry)
}

func (t tagSet) sortedKeys() []string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isCNTag(tag string) bool {
	return cnPattern.MatchString(tag)
}

func isExcludedTag(tag string) bool {
	_, ok := excludedTags[tag]
	return ok
}

func normalizeTag(tag string) string {
	tag = cnSuffixRE.ReplaceAllString(tag, "")
	return tag
}

func isCNAnnotation(annotation string) bool {
	for _, p := range strings.Split(annotation, ",@") {
		p = strings.TrimLeft(p, "@")
		if !strings.HasPrefix(p, "!") && cnPattern.MatchString(p) {
			return true
		}
	}
	return false
}

func extractDomainFromRegex(pattern string) string {
	matches := labelRE.FindAllStringSubmatch(pattern, -1)
	var parts []string
	for i := len(matches) - 1; i >= 0; i-- {
		label := matches[i][1]
		if !strictLabel.MatchString(label) {
			break
		}
		parts = append([]string{label}, parts...)
	}
	if len(parts) >= 2 {
		return strings.Join(parts, ".")
	}
	return ""
}

func processEntry(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	s = prefixRE.ReplaceAllString(s, "")
	if s == "" {
		return ""
	}
	if m := atAnnotation.FindStringSubmatch(s); m != nil {
		if isCNAnnotation(m[1]) {
			return ""
		}
		s = s[:len(s)-len(m[0])]
	}
	if s == "" {
		return ""
	}
	if regexChars.MatchString(s) {
		return extractDomainFromRegex(s)
	}
	if !strings.Contains(s, ".") && !strings.Contains(s, ":") {
		return ""
	}
	if !isIPEntry(s) && cnDomainRE.MatchString(s) {
		return ""
	}
	return s
}

func isIPEntry(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func fetch(url string) ([]byte, error) {
	var lastErr error
	for i := 0; i < retries; i++ {
		if i > 0 {
			fmt.Printf("  [попытка %d/%d] повтор: %s\n", i+1, retries, url)
			time.Sleep(retryDelay)
		}
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("ПРОПУЩЕНО после %d попыток: %w", retries, lastErr)
}

type dlcYAML struct {
	Lists []struct {
		Name  interface{} `yaml:"name"`
		Rules []string    `yaml:"rules"`
	} `yaml:"lists"`
}

func parseDLC(data []byte, out tagSet) {
	var dlc dlcYAML
	if err := yaml.Unmarshal(data, &dlc); err != nil {
		fmt.Println("  ошибка парсинга DLC YAML:", err)
		return
	}
	skipped := 0
	for _, entry := range dlc.Lists {
		tag := strings.ToLower(fmt.Sprint(entry.Name))
		tag = normalizeTag(tag)
		if isCNTag(tag) || isExcludedTag(tag) {
			skipped++
			continue
		}
		for _, rule := range entry.Rules {
			if e := processEntry(rule); e != "" {
				out.add(tag, e)
			}
		}
	}
	fmt.Printf("  обработано тегов: %d, пропущено CN: %d\n", len(dlc.Lists), skipped)
}

func parseLines(data []byte, tag string, out tagSet) {
	tag = normalizeTag(tag)
	if isExcludedTag(tag) {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if e := processEntry(line); e != "" {
			out.add(tag, e)
		}
	}
}

func main() {
	all := make(tagSet)

	fmt.Println("=== v2fly/domain-list-community ===")
	if data, err := fetch("https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml"); err != nil {
		fmt.Println(" ", err)
	} else {
		parseDLC(data, all)
	}

	fmt.Println("=== Loyalsoldier/v2ray-rules-dat (текст) ===")
	loyalsoldierBase := "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
	for _, pair := range [][2]string{
		{"proxy-list.txt", "proxy"},
		{"gfw.txt", "gfw"},
		{"reject-list.txt", "reject"},
		{"direct-list.txt", "direct"},
		{"greatfire.txt", "greatfire"},
		{"win-spy.txt", "win-spy"},
		{"win-update.txt", "win-update"},
		{"win-extra.txt", "win-extra"},
	} {
		fname, tag := pair[0], pair[1]
		if data, err := fetch(loyalsoldierBase + "/" + fname); err != nil {
			fmt.Println(" ", err)
		} else {
			parseLines(data, tag, all)
		}
	}

	fmt.Println("=== itdoginfo/allow-domains ===")
	itdogBase := "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia"
	for _, pair := range [][2]string{
		{itdogBase + "/inside-raw.lst", "itDog-russia-inside"},
		{itdogBase + "/outside-raw.lst", "itDog-russia-outside"},
	} {
		if data, err := fetch(pair[0]); err != nil {
			fmt.Println(" ", err)
		} else {
			parseLines(data, pair[1], all)
		}
	}

	fmt.Println("=== antifilter.download ===")
	for _, pair := range [][2]string{
		{"https://antifilter.download/list/allyouneed.lst", "antifilter"},
		{"https://community.antifilter.download/list/community.lst", "antifilter-community"},
		{"https://community.antifilter.download/list/domains.lst", "antifilter-community"},
	} {
		if data, err := fetch(pair[0]); err != nil {
			fmt.Println(" ", err)
		} else {
			parseLines(data, pair[1], all)
		}
	}

	fmt.Println("=== .dat файлы (protobuf) ===")
	for _, src := range []struct {
		url   string
		dtype string
	}{
		{"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip"},
		{"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat", "geoip"},
		{"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip"},
		{"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat", "geosite"},
		{"https://github.com/DanielLavrushin/b4geoip/releases/latest/download/geoip.dat", "geoip"},
	} {
		fmt.Printf("  %s\n", src.url)
		data, err := fetch(src.url)
		if err != nil {
			fmt.Println(" ", err)
			continue
		}
		if src.dtype == "geoip" {
			parseGeoIPDat(data, all)
		} else {
			parseGeoSiteDat(data, all)
		}
	}

	const maxPerFolder = 900

	fmt.Println("=== Запись lists ===")
	validTags := make([]string, 0)
	for _, tag := range all.sortedKeys() {
		if isCNTag(tag) || isExcludedTag(tag) {
			continue
		}
		if len(all[tag]) == 0 {
			continue
		}
		validTags = append(validTags, tag)
	}

	basePath := "lists"

	os.RemoveAll(basePath)
	os.MkdirAll(basePath, 0755)

	for _, tag := range validTags {
		ips := all[tag].ips()
		if len(ips) != 0 {
			path := filepath.Join(basePath, fmt.Sprintf("geoip-%s.lst", tag))
			file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				file.WriteString(fmt.Sprintf("# name: geoip:%s\n", tag))
				file.WriteString(strings.Join(ips, "\n") + "\n")
			}
			file.Close()
		}

		domains := all[tag].domains()
		if len(domains) != 0 {
			path := filepath.Join(basePath, fmt.Sprintf("geosite-%s.lst", tag))
			file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				file.WriteString(fmt.Sprintf("# name: geosite:%s\n", tag))
				file.WriteString(strings.Join(domains, "\n") + "\n")
			}
			file.Close()
		}

		//entries := all[tag].sorted()
		//
		//path := filepath.Join(basePath, fmt.Sprintf("%s-all.lst", tag))
		//file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		//if err == nil {
		//	file.WriteString(fmt.Sprintf("# name: %s (Домены + IP)\n", tag))
		//	file.WriteString(strings.Join(entries, "\n") + "\n")
		//}
		//file.Close()
	}
	fmt.Printf("  записано %d тегов\n", len(validTags))
	fmt.Println("=== Готово ===")
}
