package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gopkg.in/ini.v1"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

const configFile = "/etc/sc/config.ini"

type SSHConfig struct {
	Host  string // Server host
	Port  string // Server SSH port
	User  string // SSH username
	Pass  string // SSH user pass
	Admin string // SSH admin user
	SPass string // SSH admin pass
	Desc  string // Command description
}

// Load ini configuration and parse
func loadConfig() (map[string]SSHConfig, error) {
	cfg, err := ini.Load(configFile)
	if err != nil {
		return nil, err
	}

	sshConfigs := make(map[string]SSHConfig)
	for _, section := range cfg.Sections() {
		if section.Name() == "DEFAULT" {
			continue
		}

		sshConfigs[section.Name()] = SSHConfig{
			Host:  section.Key("host").String(),
			Port:  section.Key("port").MustString("22"),
			User:  section.Key("user").String(),
			Pass:  section.Key("pass").String(),
			Admin: section.Key("admin").String(),
			SPass: section.Key("spass").String(),
			Desc:  section.Key("desc").String(),
		}
	}

	return sshConfigs, nil
}

// set raw mode
func setRawMode(fd int) (*term.State, error) {
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return oldState, nil
}

// Connect SSH
func connectSSH(host, port, user, password string) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string,
				echos []bool) (answers []string, err error) {
				answers = make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		//HostKeyCallback: ssh.FixedHostKey(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Con't connect to %s: %v", host, err)
	}
	defer client.Close()

	// New Shell session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Can't create SSH session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Terminal setting
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	termWidth, termHeight, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		log.Fatal("unable to terminal.GetSize: %v", err)
	}
	// Connect terminal with session
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal("request for pseudo terminal failed: %v", err)
	}

	// Support TAB auto completion
	oldState, err := setRawMode(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to set raw mode:", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Handle CTRL+C
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		term.Restore(int(os.Stdin.Fd()), oldState)
		os.Exit(0)
	}()

	// Open remote shell
	err = session.Shell()
	if err != nil {
		log.Fatalf("Can't open remote shell: %v", err)
		return
	}

	// Wait for ending
	if err := session.Wait(); err != nil {
		log.Fatal("exit error: %v", err)
	}
}

func maskIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}

	type segment struct {
		index  int
		length int
	}
	segments := []segment{
		{1, len(parts[1])},
		{2, len(parts[2])},
		{3, len(parts[3])},
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].length > segments[j].length
	})

	rand.Seed(time.Now().UnixNano())
	selected := segments[:2]
	for _, s := range selected {
		parts[s.index] = "*"
	}

	return strings.Join(parts, ".")
}

func main() {
	// Load config
	sshConfigs, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  sc    [command]     Connect with normal user")
		fmt.Println("  sc -a [command]     Connect with admin user")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("")
		for name, config := range sshConfigs {
			fmt.Printf(" %-10s %-15s %s\n", name, maskIP(config.Host), config.Desc)
		}
		fmt.Println("")
		os.Exit(1)
	}

	// Handle each command
	switch os.Args[1] {
	case "-a":
		if len(os.Args) < 3 {
			fmt.Println("Usage: sc -a <section>")
			os.Exit(1)
		}
		section := os.Args[2]
		config, exists := sshConfigs[section]
		if !exists {
			fmt.Printf("Err: SSH config not found '%s'\n", section)
			os.Exit(1)
		}
		fmt.Printf("Connecting with admin user %s to %s:%s...\n", config.Admin, config.Host, config.Port)
		connectSSH(config.Host, config.Port, config.Admin, config.SPass)
	default:
		section := os.Args[1]
		config, exists := sshConfigs[section]
		if !exists {
			fmt.Printf("Err: SSH config '%s' not found\n", section)
			os.Exit(1)
		}
		fmt.Printf("Connecting with user %s to %s:%s...\n", config.User, config.Host, config.Port)
		connectSSH(config.Host, config.Port, config.User, config.Pass)
	}
}
