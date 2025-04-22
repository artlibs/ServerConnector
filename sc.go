package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	configFile = "/etc/sc/config.yml"
	keyFile    = "/etc/sc/.key" // 加密密钥文件，应当有严格权限控制
)

// 环境配置结构
type EnvConfig struct {
	SSHHome   string `yaml:"ssh_home"`
	GitConfig string `yaml:"git_config"`
	Desc      string `yaml:"desc"`
}

// 全局配置结构
type Config struct {
	SSHPath      string               `yaml:"ssh_path"`
	SSHPassPath  string               `yaml:"sshpass_path"`
	Servers      map[string]SSHConfig `yaml:"servers"`
	Environments struct {
		Current string               `yaml:"current"`
		Envs    map[string]EnvConfig `yaml:"envs"`
	} `yaml:"environments"`
}

// 单个服务器配置
type SSHConfig struct {
	Host       string `yaml:"host"`
	Port       string `yaml:"port"`
	User       string `yaml:"user"`
	Pass       string `yaml:"pass"` // 加密后的密码
	Admin      string `yaml:"admin"`
	SPass      string `yaml:"spass"`          // 加密后的管理员密码
	KeyFile    string `yaml:"key_file"`       // SSH私钥路径
	AdminKey   string `yaml:"admin_key_file"` // 管理员SSH私钥路径
	AuthMethod string `yaml:"auth_method"`    // 认证方式：key, password, ask
	Desc       string `yaml:"desc"`
}

// 加载YAML配置
func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// 设置默认值
	if config.Servers == nil {
		config.Servers = make(map[string]SSHConfig)
	}

	// 确保每个服务器配置有默认值
	for name, server := range config.Servers {
		if server.Port == "" {
			server.Port = "22"
		}
		if server.AuthMethod == "" {
			server.AuthMethod = "key" // 默认使用密钥认证
		}
		config.Servers[name] = server
	}

	return &config, nil
}

// 查找命令路径
func findCommand(command string, configPath string) (string, error) {
	// 先尝试在系统PATH中查找
	path, err := exec.LookPath(command)
	if err == nil {
		return path, nil
	}

	// 使用配置文件中的路径
	if configPath != "" {
		// 检查配置的路径是否存在
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		// 尝试将配置路径作为相对路径处理
		if !filepath.IsAbs(configPath) {
			absPath, err := filepath.Abs(configPath)
			if err == nil && fileExists(absPath) {
				return absPath, nil
			}
		}
	}

	return "", fmt.Errorf("command %s not found in system PATH or config path", command)
}

// 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 解密密码
func decryptPassword(encryptedPass string) (string, error) {
	// 如果密码为空，返回空
	if encryptedPass == "" {
		return "", nil
	}

	// 读取加密密钥
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("Cannot read encryption key: %v", err)
	}

	key := sha256.Sum256(keyData)
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPass)
	if err != nil {
		return "", err
	}

	// 检查密文长度
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("Ciphertext too short")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// 提取IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 解密
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// 加密密码 - 用于生成配置文件中的加密密码
func encryptPassword(password string) (string, error) {
	// 如果密码为空，返回空
	if password == "" {
		return "", nil
	}

	// 读取或生成加密密钥
	var keyData []byte
	if fileExists(keyFile) {
		var err error
		keyData, err = os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("Cannot read encryption key: %v", err)
		}
	} else {
		// 生成随机密钥
		keyData = make([]byte, 32)
		if _, err := rand.Read(keyData); err != nil {
			return "", fmt.Errorf("Cannot generate encryption key: %v", err)
		}

		// 保存密钥到文件，并设置严格权限
		if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
			return "", fmt.Errorf("Cannot save encryption key: %v", err)
		}
	}

	key := sha256.Sum256(keyData)
	plaintext := []byte(password)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// IV需要是唯一的，但不需要安全
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 加密
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// 转换为base64便于存储
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 获取身份验证方法
func getAuthMethod(serverConfig SSHConfig, isAdmin bool, config *Config) (string, []string, error) {
	var authType string
	var keyFile string
	var password string
	var err error

	// 确定认证方式和认证信息
	if isAdmin {
		authType = serverConfig.AuthMethod
		keyFile = serverConfig.AdminKey
		if serverConfig.SPass != "" {
			password, err = decryptPassword(serverConfig.SPass)
			if err != nil {
				return "", nil, fmt.Errorf("Failed to decrypt admin password: %v", err)
			}
		}
	} else {
		authType = serverConfig.AuthMethod
		keyFile = serverConfig.KeyFile
		if serverConfig.Pass != "" {
			password, err = decryptPassword(serverConfig.Pass)
			if err != nil {
				return "", nil, fmt.Errorf("Failed to decrypt user password: %v", err)
			}
		}
	}

	// 处理SSH密钥路径
	if keyFile != "" && !filepath.IsAbs(keyFile) {
		// 如果是相对路径，相对于用户家目录的.ssh目录
		currentUser, err := user.Current()
		if err == nil {
			keyFile = filepath.Join(currentUser.HomeDir, ".ssh", keyFile)
		}
	}

	sshOptions := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
	}

	// 根据认证方式设置选项
	switch authType {
	case "key":
		if keyFile != "" && fileExists(keyFile) {
			sshOptions = append(sshOptions, "-i", keyFile)
			return "key", sshOptions, nil
		} else if password != "" {
			// 密钥不存在但有密码，回退到密码认证
			return "password", sshOptions, nil
		} else {
			// 尝试默认密钥
			return "key", sshOptions, nil
		}
	case "password":
		if password != "" {
			return "password", sshOptions, nil
		} else {
			return "ask", sshOptions, nil // 没有存储密码，需要询问
		}
	case "ask":
		return "ask", sshOptions, nil
	default:
		return "key", sshOptions, nil // 默认使用密钥认证
	}
}

// 连接SSH
func connectSSH(host, port, user string, serverConfig SSHConfig, isAdmin bool, sshOptions []string, config *Config) error {
	authMethod, options, err := getAuthMethod(serverConfig, isAdmin, config)
	if err != nil {
		return err
	}

	// 合并SSH选项
	options = append(options, sshOptions...)

	// 查找ssh命令
	sshPath, err := findCommand("ssh", config.SSHPath)
	if err != nil {
		return fmt.Errorf("ssh not found: %v", err)
	}

	var cmd *exec.Cmd

	switch authMethod {
	case "password":
		// 使用存储的密码进行认证
		var password string
		if isAdmin {
			password, err = decryptPassword(serverConfig.SPass)
		} else {
			password, err = decryptPassword(serverConfig.Pass)
		}
		if err != nil {
			return fmt.Errorf("Failed to decrypt password: %v", err)
		}

		// 查找sshpass命令
		sshpassPath, err := findCommand("sshpass", config.SSHPassPath)
		if err != nil {
			return fmt.Errorf("sshpass not found: %v", err)
		}

		sshpassArgs := []string{"-p", password, sshPath}
		sshpassArgs = append(sshpassArgs, options...)
		sshpassArgs = append(sshpassArgs, "-p", port, fmt.Sprintf("%s@%s", user, host))

		cmd = exec.Command(sshpassPath, sshpassArgs...)
	case "ask":
		// 询问用户输入密码
		fmt.Printf("Enter password for %s: ", user)
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("Failed to read password: %v", err)
		}
		fmt.Println() // 换行

		// 查找sshpass命令
		sshpassPath, err := findCommand("sshpass", config.SSHPassPath)
		if err != nil {
			return fmt.Errorf("sshpass not found: %v", err)
		}

		sshpassArgs := []string{"-p", string(passwordBytes), sshPath}
		sshpassArgs = append(sshpassArgs, options...)
		sshpassArgs = append(sshpassArgs, "-p", port, fmt.Sprintf("%s@%s", user, host))

		cmd = exec.Command(sshpassPath, sshpassArgs...)
	case "key":
		// 使用SSH密钥认证
		sshArgs := append(options, "-p", port, fmt.Sprintf("%s@%s", user, host))
		cmd = exec.Command(sshPath, sshArgs...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
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

	// 直接使用前两个最长的段落，不需要随机选择
	selected := segments[:2]
	for _, s := range selected {
		parts[s.index] = "*"
	}

	return strings.Join(parts, ".")
}

// 用于加密配置中的密码的辅助命令
func encryptConfigPasswords() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("Failed to read config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("Failed to parse config file: %v", err)
	}

	// 加密每个服务器的密码
	for name, server := range config.Servers {
		// 只处理未加密的密码（不包含base64编码字符）
		if server.Pass != "" && !strings.Contains(server.Pass, "==") {
			encrypted, err := encryptPassword(server.Pass)
			if err != nil {
				return fmt.Errorf("Failed to encrypt password (%s): %v", name, err)
			}
			server.Pass = encrypted
		}

		if server.SPass != "" && !strings.Contains(server.SPass, "==") {
			encrypted, err := encryptPassword(server.SPass)
			if err != nil {
				return fmt.Errorf("Failed to encrypt admin password (%s): %v", name, err)
			}
			server.SPass = encrypted
		}

		config.Servers[name] = server
	}

	// 保存更新后的配置
	newData, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("Failed to serialize config: %v", err)
	}

	// 创建备份
	backupFile := configFile + ".bak." + time.Now().Format("20060102150405")
	if err := os.WriteFile(backupFile, data, 0600); err != nil {
		return fmt.Errorf("Failed to create config backup: %v", err)
	}

	// 写入新配置
	if err := os.WriteFile(configFile, newData, 0600); err != nil {
		return fmt.Errorf("Failed to save encrypted config: %v", err)
	}

	fmt.Println("Passwords encrypted and saved to config file")
	return nil
}

// 实现环境切换的主函数
func switchEnvironment(envName string, config *Config) error {
	// 获取当前环境
	currentEnv := config.Environments.Current
	if currentEnv == "" {
		currentEnv = "default"
	}

	// 获取新环境配置
	newEnvConfig, exists := config.Environments.Envs[envName]
	if !exists {
		return fmt.Errorf("Environment '%s' not defined in config", envName)
	}

	// 展开路径中的波浪号
	sshHome := newEnvConfig.SSHHome
	gitConfig := newEnvConfig.GitConfig

	// 备份当前配置
	if err := backupCurrentConfig(sshHome, gitConfig, currentEnv); err != nil {
		return err
	}

	// 检查新环境配置文件是否存在
	sshSrc := filepath.Join("/etc/sc", "ssh."+envName)
	gitSrc := filepath.Join("/etc/sc", "gitconfig."+envName)

	if !fileExists(sshSrc) || !fileExists(gitSrc) {
		// 回滚并退出
		if err := restoreFromBackup(sshHome, gitConfig, currentEnv); err != nil {
			fmt.Printf("Warning: Failed to restore backup: %v\n", err)
		}
		return fmt.Errorf("Missing required environment files: ssh.%s or gitconfig.%s", envName, envName)
	}

	// 复制新环境配置到目标位置
	if err := os.RemoveAll(sshHome); err != nil {
		return fmt.Errorf("Failed to remove existing SSH config: %v", err)
	}

	if err := copyDir(sshSrc, sshHome); err != nil {
		return fmt.Errorf("Failed to copy SSH config: %v", err)
	}

	if err := copyFile(gitSrc, gitConfig); err != nil {
		return fmt.Errorf("Failed to copy Git config: %v", err)
	}

	// 更新当前环境
	config.Environments.Current = envName
	if err := saveConfig(config); err != nil {
		return fmt.Errorf("Failed to update current environment: %v", err)
	}
	fmt.Printf("switched to env: %s\n", envName)

	return nil
}

// 备份当前配置
func backupCurrentConfig(sshHome, gitConfig, currentEnv string) error {
	knownHostsPath := filepath.Join(sshHome, "known_hosts")
	knownHostsBackup := filepath.Join("/etc/sc/"+"ssh."+currentEnv, "known_hosts")

	if fileExists(knownHostsPath) {
		if err := copyFile(knownHostsPath, knownHostsBackup); err != nil {
			return fmt.Errorf("Failed to backup known_hosts: %v", err)
		}
	}

	return nil
}

// 从备份恢复
func restoreFromBackup(sshHome, gitConfig, currentEnv string) error {
	sshBackup := filepath.Join("/etc/sc", "ssh."+currentEnv)
	gitBackup := filepath.Join("/etc/sc", "gitconfig."+currentEnv)

	if fileExists(sshBackup) {
		if err := os.RemoveAll(sshHome); err != nil {
			return err
		}
		if err := copyDir(sshBackup, sshHome); err != nil {
			return err
		}
	}

	if fileExists(gitBackup) {
		if err := copyFile(gitBackup, gitConfig); err != nil {
			return err
		}
	}

	return nil
}

// 保存配置
func saveConfig(config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
}

// 辅助函数：展开路径中的波浪号
func expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}

	currentUser, err := user.Current()
	if err != nil {
		return path
	}

	return filepath.Join(currentUser.HomeDir, path[2:])
}

// 复制目录
func copyDir(src, dst string) error {
	// 创建目标目录
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	// 获取源目录中的文件和子目录
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// 复制文件
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// 获取源文件信息以保留权限
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func main() {
	// 检查加密命令
	if len(os.Args) >= 2 && os.Args[1] == "--encrypt-config" {
		if err := encryptConfigPasswords(); err != nil {
			log.Fatalf("Failed to encrypt config: %v", err)
		}
		return
	}

	// 加载配置
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  sc [command]           Connect with normal user")
		fmt.Println("  sc [command] x         Connect with admin user")
		fmt.Println("  sc [environ] e         Switch to [environ] git & ssh config")
		fmt.Println("  sc --encrypt-config    Encrypt passwords in config.yml file")
		fmt.Println("")
		fmt.Println("Available commands:")
		fmt.Println("")
		for name, server := range config.Servers {
			fmt.Printf("  %-10s %-20s %s\n", name, maskIP(server.Host), server.Desc)
		}
		fmt.Println("")

		// 新增：显示可用环境列表
		if len(config.Environments.Envs) > 0 {
			fmt.Println("Available environments:")
			fmt.Println("")
			// 显示当前激活的环境
			currentEnv := config.Environments.Current
			if currentEnv == "" {
				currentEnv = "default"
			}
			fmt.Printf("  Current: %s\n", currentEnv)

			// 列出所有可用环境
			for name, env := range config.Environments.Envs {
				desc := env.Desc
				if desc == "" {
					desc = "No description"
				}

				// 标记当前激活的环境
				indicator := " "
				if name == currentEnv {
					indicator = "*"
				}

				fmt.Printf("  %s %-10s %s\n", indicator, name, desc)
			}
			fmt.Println("")
		}

		os.Exit(1)
	}

	// 处理环境切换命令
	if len(os.Args) == 3 && os.Args[2] == "e" {
		envName := os.Args[1]
		if err := switchEnvironment(envName, config); err != nil {
			log.Fatalf("Failed to switch environment: %v", err)
		}
		return
	}

	section := os.Args[1]
	serverConfig, exists := config.Servers[section]
	if !exists {
		fmt.Printf("Error: SSH config '%s' not found\n", section)
		os.Exit(1)
	}

	// 检查是否为管理员模式
	isAdmin := len(os.Args) > 2 && os.Args[2] == "x"

	// 传递额外的SSH参数
	var sshOptions []string
	if len(os.Args) > 2 {
		// 如果第三个参数是 "x"，则忽略它，只传递之后的参数
		if isAdmin && len(os.Args) > 3 {
			sshOptions = os.Args[3:]
		} else if !isAdmin {
			sshOptions = os.Args[2:]
		}
	}

	if isAdmin {
		fmt.Printf("Connecting with admin user %s to %s:%s...\n",
			serverConfig.Admin, serverConfig.Host, serverConfig.Port)
		err = connectSSH(serverConfig.Host, serverConfig.Port, serverConfig.Admin,
			serverConfig, true, sshOptions, config)
	} else {
		fmt.Printf("Connecting with user %s to %s:%s...\n",
			serverConfig.User, serverConfig.Host, serverConfig.Port)
		err = connectSSH(serverConfig.Host, serverConfig.Port, serverConfig.User,
			serverConfig, false, sshOptions, config)
	}

	if err != nil {
		log.Fatalf("SSH connection failed: %v", err)
	}
}
