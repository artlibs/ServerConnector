package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gopkg.in/ini.v1"
	"log"
	"os"
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Con't connect to %s: %v", host, err)
	}
	defer client.Close()

	// new Shell session
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Can't create SSH session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// terminal setting
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	termWidth, termHeight, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		log.Fatal("unable to terminal.GetSize: ", err)
	}

	// connect terminal with session
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal("request for pseudo terminal failed: ", err)
	}

	// // Set the custom prompt (e.g., using PS1 variable)
	// customPrompt := `export PS1="[\u@\h \W]$ "`
	// // Run the custom prompt setting and the shell
	// err = session.Run(fmt.Sprintf("bash -c '%s; exec bash'", customPrompt))
	err = session.Shell()
	if err != nil {
		log.Fatalf("Can't open remote shell: %v", err)
	}

	// Wait for ending
	if err := session.Wait(); err != nil {
		log.Fatal("exit error: ", err)
	}
}

func main() {
	// Load config
	sshConfigs, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  sc    <section>     Connect with normal user")
		fmt.Println("  sc -a <section>     Connect with admin user")
		fmt.Println("")
		fmt.Println("<section>")
		fmt.Println("")
		for name, config := range sshConfigs {
			fmt.Printf(" %-10s %-15s %s\n", name, config.Host, config.Desc)
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
