package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type WireguardConfig struct {
	Address    string
	ListenPort string
	PrivateKey string
	DNS        string
	MTU        string
	Server     string
	Port       string
	AllowedIPs string
	Endpoint   string
	PublicKey  string
}

func parseWireguardConfig(filePath string) (*WireguardConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &WireguardConfig{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Address = ") {
			config.Address = strings.TrimPrefix(line, "Address = ")
		} else if strings.HasPrefix(line, "ListenPort = ") {
			config.ListenPort = strings.TrimPrefix(line, "ListenPort = ")
		} else if strings.HasPrefix(line, "PrivateKey = ") {
			config.PrivateKey = strings.TrimPrefix(line, "PrivateKey = ")
		} else if strings.HasPrefix(line, "DNS = ") {
			config.DNS = strings.TrimPrefix(line, "DNS = ")
		} else if strings.HasPrefix(line, "MTU = ") {
			config.MTU = strings.TrimPrefix(line, "MTU = ")
		} else if strings.HasPrefix(line, "AllowedIPs = ") {
			config.AllowedIPs = strings.TrimPrefix(line, "AllowedIPs = ")
		} else if strings.HasPrefix(line, "Endpoint = ") {
			config.Endpoint = strings.TrimPrefix(line, "Endpoint = ")
		} else if strings.HasPrefix(line, "PublicKey = ") {
			config.PublicKey = strings.TrimPrefix(line, "PublicKey = ")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

func generateClashYAML(config *WireguardConfig) string {
	endpointParts := strings.Split(config.Endpoint, ":")
	config.Server = endpointParts[0]
	config.Port = endpointParts[1]

	var yamlBuilder strings.Builder
	yamlBuilder.WriteString("- name: \"wg\"\n")
	yamlBuilder.WriteString("  type: wireguard\n")

	if config.Address != "" {
		yamlBuilder.WriteString(fmt.Sprintf("  ip: %s\n", config.Address))
	}

	if config.PrivateKey != "" {
		yamlBuilder.WriteString(fmt.Sprintf("  private-key: %s\n", config.PrivateKey))
	}

	yamlBuilder.WriteString("  peers:\n")
	yamlBuilder.WriteString("    - server: " + config.Server + "\n")
	yamlBuilder.WriteString("      port: " + config.Port + "\n")

	if config.PublicKey != "" {
		yamlBuilder.WriteString(fmt.Sprintf("      public-key: %s\n", config.PublicKey))
	}

	yamlBuilder.WriteString("      allowed-ips: ['0.0.0.0/0']\n")
	yamlBuilder.WriteString("  udp: true\n")

	if config.MTU != "" {
		yamlBuilder.WriteString(fmt.Sprintf("  mtu: %s\n", config.MTU))
	}

	yamlBuilder.WriteString("  remote-dns-resolve: true\n")

	if config.DNS != "" {
		yamlBuilder.WriteString(fmt.Sprintf("  dns: %s\n", config.DNS))
	}

	return yamlBuilder.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("请提供Wireguard配置文件路径")
		return
	}

	configFilePath := os.Args[1]
	config, err := parseWireguardConfig(configFilePath)
	if err != nil {
		fmt.Printf("解析配置文件出错: %v\n", err)
		return
	}

	yaml := generateClashYAML(config)
	fmt.Println(yaml)
}
