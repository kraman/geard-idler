package main

import (
	"github.com/kraman/geard-idler/idler"
	"github.com/smarterclayton/cobra"
	"github.com/smarterclayton/geard/docker"
	"github.com/smarterclayton/geard/systemd"

	"net"
	"strings"
)

var (
	dockerSocket string
	hostIp       string
)

func main() {
	idlerCmd := &cobra.Command{
		Use:   "geard-idler",
		Short: "Geard-idler is a tool for monitoring containers and idling/un-idling them based on traffic",
		Run:   geardIdler,
	}
	idlerCmd.PersistentFlags().StringVarP(&dockerSocket, "docker-socket", "S", "unix:///var/run/docker.sock", "Set the docker socket to use")
	idlerCmd.PersistentFlags().StringVarP(&hostIp, "host-ip", "H", guessHostIp(), "Set the docker socket to use")

	if err := idlerCmd.Execute(); err != nil {
		idler.Fail(1, err.Error())
	}
}

func geardIdler(cmd *cobra.Command, args []string) {
	systemd.Require()

	dockerClient, err := docker.GetConnection(dockerSocket)
	if err != nil {
		idler.Fail(1, "Unable to connect to docker on URI %v", dockerSocket)
	}
	idler.NewIdler(dockerClient, hostIp).Run()
}

func guessHostIp() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "lo") ||
			strings.HasPrefix(iface.Name, "docker") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return ""
		}

		if len(addrs) == 0 {
			continue
		}

		ip, _, _ := net.ParseCIDR(addrs[0].String())
		return ip.String()
	}

	return ""
}
