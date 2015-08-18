package main

import (
	"bufio"
	"fmt"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Ip struct of attackers
type Ip struct {
	First_time time.Time
	Time_time  time.Time
	Number     int
	Counter    int
	Banned     bool
}

// Struct used to communicate between processes
type Thing struct {
	Check    bool
	Read     bool
	Mode     int
	Filename string
	Data     *string
}

// Method to step numbers of ip
func (i *Ip) step_number_ip(time_now *time.Time) {
	i.Time_time = *time_now
	i.Number++
	i.Counter++
}

// Method to reset number of attack of ip and inc number of attack by day
func (i *Ip) reset_number_ip(time_now *time.Time) {
	i.Time_time = *time_now
	i.Number = 1
	i.Counter++
}

// This func analyse if the ip who passed as a parameter whether it should be banned or not
func analyse_ip(ip *string, flashed_ip_map *map[string]Ip) bool {
	now := time.Now()
	if _, find := (*flashed_ip_map)[*ip]; find {
		if (*flashed_ip_map)[*ip].Banned {
			return false
		}
		if diff := now.Sub((*flashed_ip_map)[*ip].Time_time); diff <= (time.Duration(viper.GetInt("config.maxseconds")) * time.Second) {
			tmp := (*flashed_ip_map)[*ip]
			tmp.step_number_ip(&now)
			(*flashed_ip_map)[*ip] = tmp
		} else {
			tmp := (*flashed_ip_map)[*ip]
			tmp.reset_number_ip(&now)
			(*flashed_ip_map)[*ip] = tmp
		}

		if (*flashed_ip_map)[*ip].Number > viper.GetInt("config.requestsnumber") {
			tmp := (*flashed_ip_map)[*ip]
			tmp.Banned = true
			(*flashed_ip_map)[*ip] = tmp
			return true
		} else if (*flashed_ip_map)[*ip].Counter >= viper.GetInt("config.maxattemptsbyday") {
			if (*flashed_ip_map)[*ip].Time_time.Sub((*flashed_ip_map)[*ip].First_time) <= (86400) {
				tmp := (*flashed_ip_map)[*ip]
				tmp.Banned = true
				(*flashed_ip_map)[*ip] = tmp
				return true

			} else {
				tmp := (*flashed_ip_map)[*ip]
				tmp.Counter = 1
				tmp.First_time = tmp.Time_time
				(*flashed_ip_map)[*ip] = tmp
			}
		}
	} else {
		(*flashed_ip_map)[*ip] = Ip{First_time: now, Time_time: now, Number: 1, Counter: 1, Banned: false}
	}

	return false
}

// Append ip blacklisted to ban list
func append_to_banned_ip_list(banned_ip_list *[]string, ip_blacklist *[]string) *[]string {
	log := logging.MustGetLogger("log")
	tmp_map := make(map[string]bool)

	for _, ip := range *banned_ip_list {
		tmp_map[ip] = true
	}

	for _, ip := range *ip_blacklist {
		tmp_map[ip] = true
	}

	delete(tmp_map, "")

	new_banned_ip_list := make([]string, len(tmp_map))

	i := 0
	for k, _ := range tmp_map {
		new_banned_ip_list[i] = k
		i++
	}

	log.Debug("New list with blacklisted it: %v", new_banned_ip_list)

	return &new_banned_ip_list
}

// This func ban ip who passed as a parameter during some time
func ban_ip(ip_to_ban *string, rw_chan chan<- Thing, ban_file *string) {
	log := logging.MustGetLogger("log")
	switch viper.GetString("config.bantype") {
	case "iptables":
		ban_ip_with_iptables(&[]string{*ip_to_ban})
	case "hosts":
		ban_ip_with_hosts(ip_to_ban, rw_chan)
	case "shorewall":
		ban_ip_with_shorewall(ip_to_ban)
	}

	next_time := time.Now()
	switch viper.GetString("config.cleanupperiod") {
	case "day":
		// 3600 * 24
		next_time = next_time.Add(time.Duration(86400 * time.Second))
	case "week":
		//3600 * 24 * 7
		next_time = next_time.Add(time.Duration(604800 * time.Second))
	case "month":
		// 3600 * 24 * 30
		next_time = next_time.Add(time.Duration(2592000 * time.Second))
	}

	str := fmt.Sprintf("\n%s %d Human: %v", *ip_to_ban, next_time.Unix(), next_time)
	rw_chan <- Thing{Filename: *ban_file, Read: false, Mode: os.O_APPEND | os.O_WRONLY | os.O_CREATE, Data: &str}
	log.Notice("%s was banned until %v", *ip_to_ban, next_time)
}

// Allows ban with hosts
func ban_ip_with_hosts(ip_to_ban *string, rw_chan chan<- Thing) {
	str := "ALL: " + *ip_to_ban + "\n"
	rw_chan <- Thing{Filename: "/etc/hosts.deny", Read: false, Mode: os.O_APPEND, Data: &str}
}

// ip blacklisted are writing in hosts.deny
func ban_ip_with_hosts_for_blacklist(ip_to_ban *[]string) {
	log := logging.MustGetLogger("log")
	if len(*ip_to_ban) == 0 {
		return
	}

	fd, err := ioutil.ReadFile("/etc/hosts.deny")
	if err != nil {
		log.Critical("%v", err)
		os.Exit(1)
	}

	save := string(fd)
	hosts_string := save

	for _, ip := range *ip_to_ban {
		if !strings.Contains(save, ip) {
			hosts_string += "ALL: " + ip + "\n"
		}
	}

	err = ioutil.WriteFile("/etc/hosts.deny", []byte(hosts_string), 0644)
	if err != nil {
		log.Critical("%v", err)
		os.Exit(1)
	}

	log.Debug("/etc/hosts.deny contains: %v", hosts_string)
}

// Allows ban with iptables
func ban_ip_with_iptables(ip_to_ban *[]string) {
	log := logging.MustGetLogger("log")

	str := "iptables -I INPUT -s %s -j DROP"

	for _, ip := range *ip_to_ban {
		if _, err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Output(); err != nil {
			log.Critical("%v", err)
			os.Exit(1)
		}
		log.Debug("IP was banned: %s", ip)
	}
}

// Allows ban with shorewall
func ban_ip_with_shorewall(ip_to_ban *string) {
	log := logging.MustGetLogger("log")

	str := "shorewall deny %s"
	if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, *ip_to_ban)); err != nil {
		log.Warning("%v", err)
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save"); err != nil {
		log.Warning("%v", err)
	}
}

// using shorewall to blacklist ip
func ban_ip_with_shorewall_for_blacklist(ip_to_ban *[]string) {
	log := logging.MustGetLogger("log")
	str := "shorewall deny %s"
	for _, ip := range *ip_to_ban {
		if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)); err != nil {
			log.Warning("%v", err)
		}
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save"); err != nil {
		log.Warning("%v", err)
	}
}

// check ip, if yes, ban it if needed, else, cleaning the map with all ip who was attacking
func check_ip_process(rw_chan chan<- Thing, crash_chan chan<- string, send_data_chan chan string, whitelist *[]string, ban_file *string) {
	log := logging.MustGetLogger("log")

	ip_regex, _ := regexp.Compile("([0-9]{1,3}\\.){3}[0-9]{1,3}")
	flashed_ip_map := make(map[string]Ip)
	white_ip_map := make(map[string]bool)
	ticker := time.NewTicker(1 * time.Minute)

	log.Debug("Loading whitelist")
	for _, ip := range *whitelist {
		white_ip_map[ip] = true
	}

	// Clear whitelist
	whitelist = nil

	for {
		select {
		case new_line := <-send_data_chan:
			log.Debug("Check_ip_process receive a new line")
			ip, ok := find_attack(new_line, ip_regex, &white_ip_map)
			if ok {
				ban := analyse_ip(&ip, &flashed_ip_map)
				log.Debug("\"%s\" will be banned: %v", ip, ban)
				if ban {
					ban_ip(&ip, rw_chan, ban_file)
				}
			}
		case <-ticker.C:
			log.Debug("In check_ip_process, ticker is selected")
			now := time.Now()
			for k, v := range flashed_ip_map {
				if v.Banned {
					if now.Sub(v.Time_time) >= (24 * time.Hour) {
						log.Debug("\"%s\" don't try to connect during 24h", k)
						delete(flashed_ip_map, k)
					}
				}
			}
		}
	}

	crash_chan <- "check ip process"
}

// Clean the banned file
func clean_process(ban_file *string, rw_chan chan<- Thing, clean_chan <-chan []string, crash_chan chan<- string) {
	log := logging.MustGetLogger("log")

	for {
		rw_chan <- Thing{Filename: *ban_file, Check: false, Read: true}
		my_file := <-clean_chan

		now := time.Now()
		period_list := []float64{}
		ip_to_unban := []string{}
		ip_to_keep := []string{}

		for _, line := range my_file {
			if line == "" {
				continue
			}

			log.Debug("In clean_process line is: %s", line)

			my_split := strings.Split(line, " ")
			time_tmp, err := strconv.ParseInt(strings.Split(my_split[1], ".")[0], 10, 64)
			if err != nil {
				log.Warning(fmt.Sprintf("%s: %s", line, err))
				continue
			}
			ban_time := time.Unix(time_tmp, 0)
			log.Debug("Ban_time is: %v", ban_time)
			diff := ban_time.Sub(now)
			log.Debug("Diff is: %v", diff)
			if diff >= 0 {
				period_list = append(period_list, diff.Seconds())
				ip_to_keep = append(ip_to_keep, line)
			} else {
				ip_to_unban = append(ip_to_unban, my_split[0])
			}
		}
		log.Debug("IP will be unban: %v", ip_to_unban)
		unban_ip(rw_chan, clean_chan, &ip_to_unban)
		str := strings.Join(ip_to_keep, "\n")
		log.Debug("IP to keep: %v", str)
		rw_chan <- Thing{Filename: *ban_file, Check: false, Read: false, Mode: os.O_WRONLY | os.O_TRUNC, Data: &str}
		for _, ip := range ip_to_unban {
			log.Notice("%s was clear from \"%s\" file", ip, *ban_file)
		}

		// On s'endort
		if len(period_list) != 0 {
			log.Debug("Clean_process sleep during: %v", period_list[0])
			time.Sleep(time.Duration(period_list[0]) * time.Second)
		} else {
			a := 10
			switch viper.GetString("config.cleanupperiod") {
			case "day":
				// 3600 * 24
				a = 86400
			case "week":
				//3600 * 24 * 7
				a = 604800
			case "month":
				// 3600 * 24 * 30
				a = 2592000
			}
			log.Debug("Clean_process sleep during: %v", a)
			time.Sleep(time.Duration(a) * time.Second)
		}
	}
	crash_chan <- "clean process"
}

// find if ip should be banned or not
func find_attack(line string, ip_regex *regexp.Regexp, white_ip_map *map[string]bool) (string, bool) {
	for _, er := range viper.GetStringSlice("config.errors") {
		if strings.Contains(line, er) {
			ip := ip_regex.FindString(line)

			_, ok := (*white_ip_map)[ip]
			if ok {
				return "", false
			} else {
				return ip, true
			}
		}
	}

	return "", false
}

// Find and return local ip
func find_local_ip() string {
	log := logging.MustGetLogger("log")
	// Define the command to get locale ip
	cmd := []string{"-c", "ip a | grep \"[0-9.]\\.[0-9.]\"| awk '{print $2}' | cut -f 1 -d / | grep -v 127.0.0"}
	var counter uint8
	ip := ""
	ipTmp := []string{}

	// When computer is starting, network can put many seconds to be activated
	for {
		log.Debug("counter val: %d", counter)
		out, err := exec.Command("/bin/sh", cmd...).Output()
		if err != nil {
			log.Critical("Unable to exec command to get local ip: %s", err)
			os.Exit(1)
		}

		ipTmp = strings.Split(string(out), "\n")
		log.Debug("Output to get local ip: %s", ipTmp)

		if len(ipTmp) != 0 {
			ip = strings.Trim(ipTmp[0], " ")
			break
		}

		if counter > 15 {
			log.Critical("Unable to find correct local IP address !\n")
			os.Exit(1)
		}
		counter++
		time.Sleep(2 * time.Second)
	}

	log.Debug("Local ip is: %s", ip)

	return ip
}

// Listen for new entry. If any, it send it
func get_n_send_data_process(send_data_chan chan<- string, crash_chan chan<- string, data *bufio.Reader) {
	log := logging.MustGetLogger("log")

	for {
		new_line, _, err := data.ReadLine()
		if err != nil {
			log.Critical("%v", err)
			crash_chan <- "get_n_send_data_process"
		}
		send_data_chan <- string(new_line)
	}
	crash_chan <- "get_n_send_data_process"
}

// Getting ip who banned by iptables
func get_ip_banned_by_iptables_info() *[]string {
	log := logging.MustGetLogger("log")
	cmd := []string{"-c", "iptables -nL | grep DROP"}

	out, err := exec.Command("/bin/sh", cmd...).Output()
	if err != nil {
		log.Critical("You don't have right to execute iptables commands !")
		log.Critical("%s", err)
		os.Exit(1)
	}

	log.Debug("Output of \"iptables -nL | grep DROP\": %s", string(out))

	ip_map := make(map[string]bool)

	lines := strings.Split(string(out), "\n")
	ip_regex, _ := regexp.Compile("([0-9]{1,3}\\.){3}[0-9]{1,3}")
	for _, line := range lines {
		ip_map[ip_regex.FindString(line)] = true
	}

	ips_list := make([]string, len(ip_map))
	i := 0
	for k := range ip_map {
		ips_list[i] = k
		i++
	}

	log.Debug("IP banned by Iptables: %v", ips_list)

	return &ips_list
}

// Get ip whitelisted or blacklisted
func getting_whitelist_or_blacklist(whitelist_file *string) *[]string {
	log := logging.MustGetLogger("log")
	list := []string{}

	fd, err := ioutil.ReadFile(*whitelist_file)
	if err != nil {
		log.Debug("%s not found", *whitelist_file)
		return &list
	}

	tmplist := strings.Split(string(fd), "\n")
	list = make([]string, len(tmplist))
	i := 0
	for _, ip := range tmplist {
		if ip != "" {
			list[i] = strings.Trim(ip, " ")
			i++
		}
	}

	log.Debug("%s contain: %s", *whitelist_file, list)

	return &list
}

// Init for getting data
func init_getting_data() (*bufio.Reader, *exec.Cmd, net.Conn) {
	// http://golang.org/pkg/net/
	// http://golang-examples.tumblr.com/post/41864592909/read-stdout-of-subprocess
	log := logging.MustGetLogger("log")

	switch viper.GetString("config.log") {
	case "syslog":
		log.Debug("Using syslog to get data")
		conn := init_syslog()

		return bufio.NewReader(conn), nil, conn

	case "journalctl":
		log.Debug("Using journalctl to get data")
		out, cmd := init_journalctl()

		return bufio.NewReader(*out), cmd, nil

	default:
		log.Critical("Unknown log system !")
		os.Exit(1)
	}

	return nil, nil, nil
}

// Init for getting data with journalctl
func init_journalctl() (*io.ReadCloser, *exec.Cmd) {
	log := logging.MustGetLogger("log")
	// Test if journalctl is installed on system
	test_journalctl_str := []string{"-c", "which journalctl"}
	_, err := exec.Command("/bin/sh", test_journalctl_str...).Output()
	if err != nil {
		log.Critical("Journalctl is not install on your system !\n")
		os.Exit(1)
	}

	args := []string{"-c", "journalctl -f -u sshd.service --since now"}
	cmd := exec.Command("/bin/sh", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		log.Critical("%v", err)
	}

	if err := cmd.Start(); err != nil {
		log.Critical("%v", err)
	}

	return &out, cmd
}

// Init for getting data with syslog
func init_syslog() net.Conn {
	log := logging.MustGetLogger("log")
	// Test if syslog-ng is installed on system
	test_syslogng_str := []string{"-c", "which syslog-ng"}
	_, err := exec.Command("/bin/sh", test_syslogng_str...).Output()
	if err != nil {
		log.Critical("Syslog-ng is not install on your system !\n")
		os.Exit(1)
	}

	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(viper.GetInt("config.listenport")))
	if err != nil {
		log.Critical("%v", err)
		os.Exit(1)
	}
	// Try to listen port
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Critical("%v", err)
		os.Exit(1)
	}

	return sock
}

// Load already banned ip
func load_banned_ip(ban_file *string) *[]string {
	log := logging.MustGetLogger("log")
	flash_ip_list := []string{}

	fd, err := ioutil.ReadFile(*ban_file)
	if err != nil {
		log.Warning("\"%s\" don't exist or it is unable to read it: %s", *ban_file, err)
		return &flash_ip_list
	}

	flash_ip_list = make([]string, 0, len(strings.Split(string(fd), "\n")))
	i := 0
	for _, data := range strings.Split(string(fd), "\n") {
		if data == "" {
			continue
		}
		tmp := strings.Split(data, " ")
		if tmp[0] != "" {
			flash_ip_list[i] = tmp[0]
			i++
		}
	}

	return &flash_ip_list
}

// Before banning ip, it remowe which are already
func remove_ip_already_banned(ip_iptables_list *[]string, banned_ip_file_list *[]string) *[]string {
	log := logging.MustGetLogger("log")

	ip_will_be_banned := []string{}
	for _, i := range *banned_ip_file_list {
		tmp := false
		for _, j := range *ip_iptables_list {
			if i == j {
				tmp = true
				break
			}
		}
		if !tmp {
			ip_will_be_banned = append(ip_will_be_banned, i)
		}
	}

	log.Debug("IP will be banned after remove banned IP: %v", ip_will_be_banned)

	return &ip_will_be_banned
}

// It read or write on demand
func read_write_process(rw_chan <-chan Thing, check_chan chan<- []string, clean_chan chan<- []string, crash_chan chan<- string) {
	log := logging.MustGetLogger("log")

	for {
		obj := <-rw_chan
		if obj.Read {
			fd, err := ioutil.ReadFile(obj.Filename)
			if err != nil {
				log.Critical("Unable to read file \"%s\": %v", obj.Filename, err)
				crash_chan <- "read_write_process"
			}
			if obj.Check {
				check_chan <- strings.Split(string(fd), "\n")
			} else {
				clean_chan <- strings.Split(string(fd), "\n")
			}
		} else {
			fd, err := os.OpenFile(obj.Filename, obj.Mode, 0644)
			if err != nil {
				log.Critical("Unable to open \"%s\", %v", obj.Filename, err)
				crash_chan <- "read_write_process"
			}
			defer fd.Close()

			w := bufio.NewWriter(fd)
			if _, err := w.WriteString(*obj.Data); err != nil {
				log.Critical("Unable to write into \"%s\": %v", obj.Filename, err)
				crash_chan <- "read_write_process"
			}
			if err := w.Flush(); err != nil {
				log.Critical("Unable to flush \"%s\": %v", obj.Filename, err)
				crash_chan <- "read_write_process"
			}
		}
	}

	crash_chan <- "read_write_process"
}

// Research identical ip in blacklist and whitelist
func research_identical_ip(blacklist *[]string, whitelist *[]string) {
	log := logging.MustGetLogger("log")
	if len(*blacklist) == 0 || len(*whitelist) == 0 {
		return
	}
	set := make(map[string]bool, len(*blacklist))

	for _, ip := range *blacklist {
		set[ip] = true
	}

	findIt := false
	for _, ip := range *whitelist {
		_, ok := set[ip]
		if ok {
			findIt = true
			log.Critical("%v is in whitelist and blacklist !\n\n", ip)
		}
	}
	if findIt {
		os.Exit(1)
	}
}

// Unban ip with differents methodes
func unban_ip(rw_chan chan<- Thing, clean_chan <-chan []string, ip_to_unban *[]string) {
	switch viper.GetString("config.bantype") {
	case "iptables":
		unban_ip_with_iptables(ip_to_unban)
	case "hosts":
		unban_ip_with_hosts_deny(ip_to_unban, rw_chan, clean_chan)
	case "shorewall":
		unban_ip_with_shorewall(ip_to_unban)
	}
}

// Unban ip with on /etc/hosts.deny
func unban_ip_with_hosts_deny(ip_to_unban *[]string, rw_chan chan<- Thing, clean_chan <-chan []string) {
	rw_chan <- Thing{Filename: "/etc/hosts.deny", Check: false, Read: true}
	hosts_file := <-clean_chan

	new_file := make([]string, 0)

	for _, line := range hosts_file {
		if line == "" {
			new_file = append(new_file, "\n")
		}

		find := false
		for _, ip := range *ip_to_unban {
			if strings.Contains(line, ip) {
				find = true
				break
			}
		}
		if !find {
			new_file = append(new_file, line)
		}
	}
	str := strings.Join(new_file, "\n")
	rw_chan <- Thing{Filename: "/etc/hosts.deny", Check: false, Read: false, Mode: os.O_WRONLY | os.O_TRUNC, Data: &str}
}

// Unban ip with iptables
func unban_ip_with_iptables(ip_to_unban *[]string) {
	log := logging.MustGetLogger("log")
	str := "iptables -D INPUT -s %s -j DROP"
	for _, ip := range *ip_to_unban {
		if _, err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Output(); err != nil {
			log.Warning("%v", err)
		}
	}
}

// Unban ip with shorewall
func unban_ip_with_shorewall(ip_to_unban *[]string) {
	log := logging.MustGetLogger("log")
	str := "shorewall allow %s"
	for _, ip := range *ip_to_unban {
		if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Start(); err != nil {
			log.Warning("%v", err)
		}
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save").Start(); err != nil {
		log.Warning("%v", err)
	}
}

// wait some command, mainly journalctl otherwise journalctl pipe crashed
func wait_cmd(cmd *exec.Cmd, conn net.Conn) {
	switch viper.GetString("config.bantype") {
	case "syslog":
	case "journalctl":
		cmd.Wait()
	}
}

func main() {
	/*
		ban_file := "banned_ip"
		logFile := "log.log"
		confPath := "cfg"
		confFile := "sshd_autoban_sample"
		whitelist_file := "whitelist"
		blacklist_file := "blacklist"
	*/

	ban_file := "/var/log/sshd_autoban/banned_ip"
	logFile := "/var/log/sshd_autoban/errors.log"
	confPath := "/etc/sshd_autoban"
	confFile := "sshd_autoban"
	whitelist_file := "/etc/sshd_autoban/whitelist"
	blacklist_file := "/etc/sshd_autoban/blacklist"

	rw_chan := make(chan Thing)
	check_chan := make(chan []string)
	clean_chan := make(chan []string)
	crash_chan := make(chan string)
	send_data_chan := make(chan string, 60)

	fd := initLogging(&logFile)
	defer fd.Close()

	loadConfig(&confPath, &confFile)

	/*
		if viper.GetString("config.localip") == "auto" {
			viper.SetDefault("localip", find_local_ip())
		}
	*/

	ip_blacklist := getting_whitelist_or_blacklist(&blacklist_file)
	ip_whitelist := getting_whitelist_or_blacklist(&whitelist_file)

	research_identical_ip(ip_blacklist, ip_whitelist)

	banned_ip_list := load_banned_ip(&ban_file)
	banned_ip_list = append_to_banned_ip_list(banned_ip_list, ip_blacklist)

	// Faire un select ici pour bannir les ip blacklist avec les autres méthodes
	switch viper.GetString("config.bantype") {
	case "hosts":
		ban_ip_with_hosts_for_blacklist(ip_blacklist)
	case "iptables":
		ip_iptables_list := get_ip_banned_by_iptables_info()
		ip_to_ban := remove_ip_already_banned(ip_iptables_list, banned_ip_list)
		ban_ip_with_iptables(ip_to_ban)
	case "shorewall":
		ban_ip_with_shorewall_for_blacklist(ip_blacklist)
	}

	// Clear banned_ip_list
	banned_ip_list = nil
	// Clear blacklist
	ip_blacklist = nil

	data, cmd, conn := init_getting_data()

	log := logging.MustGetLogger("log")
	log.Notice("** Starting analysis **")

	go read_write_process(rw_chan, check_chan, clean_chan, crash_chan)
	go clean_process(&ban_file, rw_chan, clean_chan, crash_chan)
	go check_ip_process(rw_chan, crash_chan, send_data_chan, ip_whitelist, &ban_file)
	go get_n_send_data_process(send_data_chan, crash_chan, data)
	go wait_cmd(cmd, conn)

	reply := <-crash_chan
	log.Critical("Goroutine \"%v\" crashed !", reply)
	os.Exit(1)
}
