package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/kraman/geard-idler/config"
	"github.com/smarterclayton/geard/containers"
	"github.com/smarterclayton/geard/docker"
	"os/exec"
	"strconv"
	"strings"
)

func runIptablesRules(add bool, hostIp string, port string, id containers.Identifier) error {
	command := []string{"/sbin/iptables"}
	if config.UsePreroutingIdler {
		if add {
			command = append(command, "-t", "nat", "-I", "PREROUTING", "1")
		} else {
			command = append(command, "-t", "nat", "-D", "PREROUTING")
		}
	} else {
		if add {
			command = append(command, "-I", "INPUT", "1")
		} else {
			command = append(command, "-D", "INPUT")
		}
	}

	command = append(command, "-d", hostIp, "-p", "tcp", "-m", "tcp", "--dport", port)
	command = append(command, "-j", "NFQUEUE", "--queue-num", "0")
	command = append(command, "-m", "comment", "--comment", string(id))
	fmt.Println(command)
	return exec.Command(command[0], command[1:]...).Run()
}

func IdleContainer(id containers.Identifier, hostIp string) {
	portPairs, err := containers.GetExistingPorts(id)
	if err != nil {
		fmt.Printf("IDLE: Error retrieving ports for container: %v", id)
		return
	}

	for _, portPair := range portPairs {
		port := portPair.External
		runIptablesRules(false, hostIp, port.String(), id)
		runIptablesRules(true, hostIp, port.String(), id)
	}
}

func UnidleContainer(id containers.Identifier, hostIp string) {
	portPairs, err := containers.GetExistingPorts(id)
	if err != nil {
		fmt.Printf("IDLE: Error retrieving ports for container: %v", id)
		return
	}

	for _, portPair := range portPairs {
		port := portPair.External
		runIptablesRules(false, hostIp, port.String(), id)
	}
}

func GetDockerContainerPacketCounts(d *docker.DockerClient) (map[containers.Identifier]int, error) {
	ips, err := containers.GetAllContainerIPs(d)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("/sbin/iptables-save", "-c")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	scan := bufio.NewScanner(bytes.NewBuffer(output))
	packetCount := make(map[string]int)

	for scan.Scan() {
		line := scan.Text()
		if !strings.Contains(line, "-A DOCKER ! -i docker0") || !strings.Contains(line, "-j DNAT") {
			continue
		}

		items := strings.Fields(line)
		packets, _ := strconv.Atoi(strings.Split(items[0], ":")[0][1:])
		destIp := strings.Split(items[15], ":")[0]
		packetCount[destIp] = packetCount[destIp] + packets
	}

	containerPackerCount := make(map[containers.Identifier]int)
	for id, ip := range ips {
		containerPackerCount[id] = packetCount[ip]
	}
	return containerPackerCount, nil
}

func GetIdlerRules(lookupId containers.Identifier) (map[string]bool, error) {
	cmd := exec.Command("/sbin/iptables-save", "-c")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	scan := bufio.NewScanner(bytes.NewBuffer(output))
	ports := make(map[string]bool)

	for scan.Scan() {
		line := scan.Text()
		if (config.UsePreroutingIdler && !strings.Contains(line, "-A PREROUTING")) ||
			(!config.UsePreroutingIdler && !strings.Contains(line, "-A INPUT")) ||
			!strings.Contains(line, "-j NFQUEUE --queue-num 0") {
			continue
		}

		items := strings.Fields(line)
		port := items[10]
		id, err := containers.NewIdentifier(items[14])
		if err != nil {
			return nil, err
		}

		if id != lookupId {
			continue
		}

		ports[port] = true
	}
	return ports, nil
}

func ResetPacketCount() error {
	return exec.Command("/sbin/iptables", "-t", "nat", "-L", "DOCKER", "-Z").Run()
}
