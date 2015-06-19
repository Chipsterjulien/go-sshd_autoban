package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Global var
var logger *log.Logger

// Struct of config json
type Configuration struct {
	Requests_number     int      // Number of authorized requests
	Max_seconds         int      // If number of authorized requests will be over in max seconds, the ip will be banned
	Max_attempts_by_day int      // Number of requests by day. If it over, ip will be ban
	Listen_port         int      // The port where sshd_autoban listen
	Ban_type            string   // Which ban method
	Cleanup_period      string   // (day, week, month, never) Clean banned ip
	Local_ip            string   // (auto) Define the ip address
	Log                 string   // (journalctl, syslog) Which method of log
	Errors              []string // Intercept errors
}

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
func analyse_ip(ip *string, flashed_ip_map *map[string]Ip, conf_obj *Configuration) bool {
	now := time.Now()
	if _, find := (*flashed_ip_map)[*ip]; find {
		if (*flashed_ip_map)[*ip].Banned {
			return false
		}
		if diff := now.Sub((*flashed_ip_map)[*ip].Time_time); diff <= (time.Duration(conf_obj.Max_seconds) * time.Second) {
			tmp := (*flashed_ip_map)[*ip]
			tmp.step_number_ip(&now)
			(*flashed_ip_map)[*ip] = tmp
		} else {
			tmp := (*flashed_ip_map)[*ip]
			tmp.reset_number_ip(&now)
			(*flashed_ip_map)[*ip] = tmp
		}

		if (*flashed_ip_map)[*ip].Number > conf_obj.Requests_number {
			tmp := (*flashed_ip_map)[*ip]
			tmp.Banned = true
			(*flashed_ip_map)[*ip] = tmp
			return true
		} else if (*flashed_ip_map)[*ip].Counter >= conf_obj.Max_attempts_by_day {
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

// Append ip blacklistet to ban list
func append_to_banned_ip_list(banned_ip_list *[]string, ip_blacklist *[]string) *[]string {
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

	return &new_banned_ip_list
}

// This func ban ip who passed as a parameter during some time
func ban_ip(ip_to_ban *string, conf_obj *Configuration, rw_chan chan<- Thing, ban_file *string) {
	switch conf_obj.Ban_type {
	case "iptables":
		ban_ip_with_iptables(&[]string{*ip_to_ban}, conf_obj)
	case "hosts":
		ban_ip_with_hosts(ip_to_ban, rw_chan)
	case "shorewall":
		ban_ip_with_shorewall(ip_to_ban)
	}

	next_time := time.Now()
	switch conf_obj.Cleanup_period {
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
	rw_chan <- Thing{Filename: *ban_file, Read: false, Mode: os.O_APPEND | os.O_WRONLY, Data: &str}
	logger.Println(fmt.Sprintf("%s was banned until %v", *ip_to_ban, next_time))
}

// Allows ban with hosts
func ban_ip_with_hosts(ip_to_ban *string, rw_chan chan<- Thing) {
	str := "ALL: " + *ip_to_ban + "\n"
	rw_chan <- Thing{Filename: "/etc/hosts.deny", Read: false, Mode: os.O_APPEND, Data: &str}
}

// ip blacklisted are writing in hosts.deny
func ban_ip_with_hosts_for_blacklist(ip_to_ban *[]string) {
	if len(*ip_to_ban) == 0 {
		return
	}

	fd, err := ioutil.ReadFile("/etc/hosts.deny")
	if err != nil {
		logger.Fatal(err)
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
		logger.Fatal(err)
	}
}

// Allows ban with iptables
func ban_ip_with_iptables(ip_to_ban *[]string, conf_obj *Configuration) {
	str := "iptables -I INPUT -s %s -j DROP"

	for _, ip := range *ip_to_ban {
		if _, err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Output(); err != nil {
			logger.Println(err)
		}
	}
}

// Allows ban with shorewall
func ban_ip_with_shorewall(ip_to_ban *string) {
	str := "shorewall deny %s"
	if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, *ip_to_ban)); err != nil {
		logger.Println(err)
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save"); err != nil {
		logger.Println(err)
	}
}

// using shorewall to blacklist ip
func ban_ip_with_shorewall_for_blacklist(ip_to_ban *[]string) {
	str := "shorewall deny %s"
	for _, ip := range *ip_to_ban {
		if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)); err != nil {
			logger.Println(err)
		}
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save"); err != nil {
		logger.Println(err)
	}
}

// Check if file can be read, write or create
func check_file(my_file *string, read bool, write bool, create bool) {
	if create {
		if _, err := os.OpenFile(*my_file, os.O_APPEND|os.O_CREATE, 0644); err != nil {
			log.Fatal("Unable to create \"", *my_file, "\": ", err)
		}
	}

	if read {
		if _, err := os.OpenFile(*my_file, os.O_RDONLY, 0644); err != nil {
			log.Fatal("Unable to read \"", *my_file, "\": ", err)
		}
	}

	if write {
		if _, err := os.OpenFile(*my_file, os.O_WRONLY, 0644); err != nil {
			log.Fatal("Unable to write in \"", *my_file, "\": ", err)
		}
	}
}

// check ip, if yes, ban it if needed, else, cleaning the map with all ip who was attacking
func check_ip_process(conf_obj *Configuration, rw_chan chan<- Thing, crash_chan chan<- string, send_data_chan chan string, whitelist *[]string, ban_file *string) {
	ip_regex, _ := regexp.Compile("([0-9]{1,3}\\.){3}[0-9]{1,3}")
	flashed_ip_map := make(map[string]Ip)
	white_ip_map := make(map[string]bool)
	ticker := time.NewTicker(1 * time.Minute)

	for _, ip := range *whitelist {
		white_ip_map[ip] = true
	}

	// Clear whitelist
	whitelist = nil

	for {
		select {
		case new_line := <-send_data_chan:
			ip, ok := find_attack(conf_obj, new_line, ip_regex, &white_ip_map)
			if ok {
				ban := analyse_ip(&ip, &flashed_ip_map, conf_obj)
				if ban {
					ban_ip(&ip, conf_obj, rw_chan, ban_file)
				}
			}
		case <-ticker.C:
			now := time.Now()
			for k, v := range flashed_ip_map {
				if v.Banned {
					if now.Sub(v.Time_time) >= (24 * time.Hour) {
						delete(flashed_ip_map, k)
					}
				}
			}
		}
	}
}

// Clean the banned file
func clean_process(conf_obj *Configuration, ban_file *string, rw_chan chan<- Thing, clean_chan <-chan []string, crash_chan chan<- string) {
	for {
		rw_chan <- Thing{Filename: *ban_file, Check: false, Read: true}
		my_file := <-clean_chan

		now := time.Now()
		period_list := make([]float64, 0)
		ip_to_unban := make([]string, 0)
		ip_to_keep := make([]string, 0)

		for _, line := range my_file {
			if line == "" {
				continue
			}
			my_split := strings.Split(line, " ")
			time_tmp, err := strconv.ParseInt(strings.Split(my_split[1], ".")[0], 10, 64)
			if err != nil {
				logger.Println(fmt.Sprintf("%s: %s", line, err))
				continue
			}
			ban_time := time.Unix(time_tmp, 0)
			diff := ban_time.Sub(now)
			if diff >= 0 {
				period_list = append(period_list, diff.Seconds())
				ip_to_keep = append(ip_to_keep, line)
			} else {
				ip_to_unban = append(ip_to_unban, my_split[0])
			}
		}
		unban_ip(conf_obj, rw_chan, clean_chan, &ip_to_unban)
		str := strings.Join(ip_to_keep, "\n")
		rw_chan <- Thing{Filename: *ban_file, Check: false, Read: false, Mode: os.O_WRONLY | os.O_TRUNC, Data: &str}
		for _, ip := range ip_to_unban {
			logger.Println(fmt.Sprintf("%s was clear from \"%s\" file", ip, *ban_file))
		}

		// On s'endort
		if len(period_list) != 0 {
			time.Sleep(time.Duration(period_list[0]) * time.Second)
		} else {
			a := 10
			switch conf_obj.Cleanup_period {
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
			time.Sleep(time.Duration(a) * time.Second)
		}
	}
}

// find if ip should be banned or not
func find_attack(conf_obj *Configuration, line string, ip_regex *regexp.Regexp, white_ip_map *map[string]bool) (string, bool) {
	for _, er := range conf_obj.Errors {
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
	// Define the command to get locale ip
	cmd := []string{"-c", "ip a | grep --color=auto \"[0-9.]\\.[0-9.]\"| awk '{print $2}' | cut -f 1 -d / | grep -v 127.0.0"}
	var counter uint8

	// When computer is starting, network can put many seconds to be activated
	for {
		out, err := exec.Command("/bin/sh", cmd...).Output()
		if err != nil {
			logger.Fatal(err)
		}

		ip := strings.Split(string(out), "\n")

		if len(ip) != 0 {
			return strings.Trim(ip[0], " ")
		}

		if counter > 15 {
			logger.Fatal("Unable to find correct local IP address !\n")
		}
		counter++
		time.Sleep(2 * time.Second)
	}
}

// Listen for new entry. If any, it send it
func get_n_send_data_process(send_data_chan chan<- string, crash_chan chan<- string, data *bufio.Reader) {
	for {
		new_line, _, err := data.ReadLine()
		if err != nil {
			logger.Println(err)
			crash_chan <- "get_n_send_data_process"
		}
		send_data_chan <- string(new_line)
	}
}

// Getting ip who banned by iptables
func get_ip_banned_by_iptables_info() *[]string {
	cmd := []string{"-c", "iptables -nL |grep DROP"}

	out, err := exec.Command("/bin/sh", cmd...).Output()
	if err != nil {
		logger.Println("You don't have right to execute iptables commands !")
		logger.Fatal(err)
	}

	ip_map := make(map[string]bool)

	ip_regex, _ := regexp.Compile("([0-9]{1,3}\\.){3}[0-9]{1,3}")
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		ip_map[ip_regex.FindString(line)] = true
	}

	ips_list := make([]string, len(ip_map))
	i := 0
	for k := range ip_map {
		ips_list[i] = k
		i++
	}

	return &ips_list
}

// Get ip whitelisted or blacklisted
func getting_whitelist_or_blacklist(whitelist_file *string) *[]string {
	fd, err := ioutil.ReadFile(*whitelist_file)
	if err != nil {
		logger.Println(*whitelist_file, "not found !")
		return &[]string{}
	}

	tmplist := strings.Split(string(fd), "\n")
	my_list := make([]string, len(tmplist))
	i := 0
	for _, ip := range tmplist {
		if ip != "" {
			my_list[i] = strings.Trim(ip, " ")
		}
		i++
	}

	return &my_list
}

// Init for getting data
func init_getting_data(conf_obj *Configuration) (*bufio.Reader, *exec.Cmd, net.Conn) {
	// http://golang.org/pkg/net/
	// http://golang-examples.tumblr.com/post/41864592909/read-stdout-of-subprocess
	switch conf_obj.Log {
	case "syslog":
		conn := init_syslog(conf_obj)

		return bufio.NewReader(conn), nil, conn

	case "journalctl":
		out, cmd := init_journalctl(conf_obj)

		return bufio.NewReader(*out), cmd, nil

	default:
		logger.Fatal("Unknown log system !")
	}

	return nil, nil, nil
}

// Init for getting data with journalctl
func init_journalctl(conf_obj *Configuration) (*io.ReadCloser, *exec.Cmd) {
	// Test if journalctl is installed on system
	test_journalctl_str := []string{"-c", "which journalctl"}
	_, err := exec.Command("/bin/sh", test_journalctl_str...).Output()
	if err != nil {
		logger.Fatal("Journalctl is not install on your system !\n")
	}

	args := []string{"-c", "journalctl -f -u sshd.service --since now"}
	cmd := exec.Command("/bin/sh", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		logger.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		logger.Fatal(err)
	}
	return &out, cmd
}

// Init for getting data with syslog
func init_syslog(conf_obj *Configuration) net.Conn {
	// Test if syslog-ng is installed on system
	test_syslogng_str := []string{"-c", "which syslog-ng"}
	_, err := exec.Command("/bin/sh", test_syslogng_str...).Output()
	if err != nil {
		logger.Fatal("Syslog-ng is not install on your system !\n")
	}

	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(conf_obj.Listen_port))
	if err != nil {
		logger.Fatal(err)
	}
	// Try to listen port
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Fatal(err)
	}

	return sock
}

// Load already banned ip
func load_banned_ip(ban_file *string) *[]string {
	fd, err := ioutil.ReadFile(*ban_file)
	if err != nil {
		logger.Fatal(err)
	}

	flash_ip_list := make([]string, 0, len(strings.Split(string(fd), "\n")))
	for _, data := range strings.Split(string(fd), "\n") {
		if data == "" {
			continue
		}
		tmp := strings.Split(data, " ")
		if tmp[0] != "" {
			flash_ip_list = append(flash_ip_list, tmp[0])
		}
	}

	return &flash_ip_list
}

// Load json config file and return an object
func load_conf(conf_file *string, logger *log.Logger) *Configuration {
	var config Configuration
	file, err := ioutil.ReadFile(*conf_file)
	if err != nil {
		logger.Fatal(err)
	}
	json.Unmarshal(file, &config)

	return &config
}

// Before banning ip, it remowe which are already
func remove_ip_already_banned(ip_iptables_list *[]string, banned_ip_file_list *[]string) *[]string {
	ip_will_be_banned := make([]string, 0)
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

	return &ip_will_be_banned
}

// It read or write on demand
func read_write_process(rw_chan <-chan Thing, check_chan chan<- []string, clean_chan chan<- []string, crash_chan chan<- string) {
	for {
		obj := <-rw_chan
		if obj.Read {
			fd, err := ioutil.ReadFile(obj.Filename)
			if err != nil {
				logger.Println(err)
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
				logger.Println(err)
				crash_chan <- "read_write_process"
			}
			defer fd.Close()

			w := bufio.NewWriter(fd)
			if _, err := w.WriteString(*obj.Data); err != nil {
				logger.Println(err)
				crash_chan <- "read_write_process"
			}
			if err := w.Flush(); err != nil {
				logger.Println(err)
				crash_chan <- "read_write_process"
			}
			// Clearing slice (useless)
			//obj.Data = obj.Data[:0]
		}
	}
}

// Research identical ip in blacklist and whitelist
func research_identical_ip(blacklist *[]string, whitelist *[]string) {
	if len(*blacklist) == 0 || len(*whitelist) == 0 {
		return
	}
	set := make(map[string]bool, len(*blacklist))

	for _, ip := range *blacklist {
		set[ip] = true
	}

	for _, ip := range *whitelist {
		_, ok := set[ip]
		if ok {
			logger.Fatal(fmt.Sprintf("%v is in whitelist and blacklist !\n\n", ip))
		}
	}
}

// Init log
func setting_logging(log_file *string) *os.File {
	fd, err := os.OpenFile(*log_file, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(fd)
	logger = log.New(io.MultiWriter(fd, os.Stdout), "", log.Ldate|log.Lshortfile|log.Ltime)

	return fd
}

// Unban ip with differents methodes
func unban_ip(conf_obj *Configuration, rw_chan chan<- Thing, clean_chan <-chan []string, ip_to_unban *[]string) {
	switch conf_obj.Ban_type {
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
	str := "iptables -D INPUT -s %s -j DROP"
	for _, ip := range *ip_to_unban {
		if _, err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Output(); err != nil {
			logger.Println(err)
		}
	}
}

// Unban ip with shorewall
func unban_ip_with_shorewall(ip_to_unban *[]string) {
	str := "shorewall allow %s"
	for _, ip := range *ip_to_unban {
		if err := exec.Command("/bin/sh", "-c", fmt.Sprintf(str, ip)).Start(); err != nil {
			logger.Println(err)
		}
	}
	if err := exec.Command("/bin/sh", "-c", "shorewall save").Start(); err != nil {
		logger.Println(err)
	}
}

// wait some command, mainly journalctl otherwise journalctl pipe crashed
func wait_cmd(conf_obj *Configuration, cmd *exec.Cmd, conn net.Conn) {
	switch conf_obj.Ban_type {
	case "syslog":
	case "journalctl":
		cmd.Wait()
	}
}

func main() {
	/*ban_file := "banned_ip"
	log_file := "log.log"
	conf_file := "cfg/sshd_autoban_example.json"
	whitelist_file := "whitelist"
	blacklist_file := "blacklist"*/

	ban_file := "/var/log/sshd_autoban/banned_ip"
	log_file := "/var/log/sshd_autoban/main.log"
	conf_file := "/etc/sshd_autoban/sshd_autoban.json"
	whitelist_file := "/etc/sshd_autoban/whitelist"
	blacklist_file := "/etc/sshd_autoban/blacklist"

	check_file(&log_file, true, true, true)
	check_file(&ban_file, true, true, true)
	check_file(&conf_file, true, false, false)

	rw_chan := make(chan Thing)
	check_chan := make(chan []string)
	clean_chan := make(chan []string)
	crash_chan := make(chan string)
	send_data_chan := make(chan string, 60)

	fd_log := setting_logging(&log_file)
	defer fd_log.Close()

	conf_obj := load_conf(&conf_file, logger)

	if conf_obj.Local_ip == "auto" {
		conf_obj.Local_ip = find_local_ip()
	}

	ip_blacklist := getting_whitelist_or_blacklist(&blacklist_file)
	ip_whitelist := getting_whitelist_or_blacklist(&whitelist_file)

	research_identical_ip(ip_blacklist, ip_whitelist)

	banned_ip_list := load_banned_ip(&ban_file)
	banned_ip_list = append_to_banned_ip_list(banned_ip_list, ip_blacklist)

	// Faire un select ici pour bannir les ip blacklist avec les autres méthodes
	switch conf_obj.Ban_type {
	case "hosts":
		ban_ip_with_hosts_for_blacklist(ip_blacklist)
	case "iptables":
		ip_iptables_list := get_ip_banned_by_iptables_info()
		ip_to_ban := remove_ip_already_banned(ip_iptables_list, banned_ip_list)
		ban_ip_with_iptables(ip_to_ban, conf_obj)
	case "shorewall":
		ban_ip_with_shorewall_for_blacklist(ip_blacklist)
	}

	// Clear banned_ip_list
	banned_ip_list = nil
	// Clear blacklist
	ip_blacklist = nil

	data, cmd, conn := init_getting_data(conf_obj)

	logger.Println("** Starting analysis **")

	go read_write_process(rw_chan, check_chan, clean_chan, crash_chan)
	go clean_process(conf_obj, &ban_file, rw_chan, clean_chan, crash_chan)
	go check_ip_process(conf_obj, rw_chan, crash_chan, send_data_chan, ip_whitelist, &ban_file)
	go get_n_send_data_process(send_data_chan, crash_chan, data)
	go wait_cmd(conf_obj, cmd, conn)

	reply := <-crash_chan
	logger.Fatal(fmt.Sprintf("Goroutine \"%s\" crashed !", reply))
}
