package idler

import (
	"github.com/kraman/go-netfilter-queue"
	"github.com/smarterclayton/geard/containers"
	"github.com/smarterclayton/geard/docker"
	"github.com/smarterclayton/geard/systemd"

	"github.com/kraman/geard-idler/config"
	"github.com/kraman/geard-idler/iptables"

	"code.google.com/p/gopacket/layers"
	"fmt"
	"strconv"
	"time"
)

type Idler struct {
	d            *docker.DockerClient
	qh           []*netfilter.NFQueue
	waitChan     chan uint16
	openChannels []containers.Identifier
	hostIp       string
}

func NewIdler(d *docker.DockerClient, hostIp string) *Idler {
	var err error

	idler := Idler{}
	idler.d = d
	idler.qh = make([]*netfilter.NFQueue, config.NumQueues)
	idler.waitChan = make(chan uint16)
	idler.openChannels = make([]containers.Identifier, config.NumQueues)
	idler.hostIp = hostIp
	for i := 0; i < config.NumQueues; i++ {
		idler.qh[i], err = netfilter.NewNFQueue(uint16(i), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
		if err != nil {
			Fail(2, "Unable to open Netfilter Queue: %v", err)
		}
	}

	return &idler
}

func (idler *Idler) Run() {
	for i := range idler.qh {
		if i >= 1 {
			go waitStart(idler.qh[i].GetPackets(), uint16(i), idler.waitChan, idler.hostIp)
		}
	}

	packets := idler.qh[0].GetPackets()
	ticker := time.NewTicker(time.Second * 30)

	for true {
		select {
		case chanId := <-idler.waitChan:
			idler.openChannels[chanId] = ""
		case p := <-packets:
			id, err := identifierForPacket(p)
			if err != nil {
				fmt.Println(err)
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			idler.unidleContainer(id, p)
		case <-ticker.C:
			cpkt, err := iptables.GetDockerContainerPacketCounts(idler.d)
			if err != nil {
				fmt.Printf("Error retrieving packet counts for containers: %v\n", err)
			}
			iptables.ResetPacketCount()
			for id, pkts := range cpkt {
				if pkts == 0 {
					idler.idleContainer(id)
				}
			}
		}
	}
}

func (idler *Idler) unidleContainer(id containers.Identifier, p netfilter.NFPacket) {
	newChanId, wasAlreadyAssigned := idler.getAvailableWaiter(id)

	if newChanId == 0 {
		fmt.Println("unidle: Error while finding wait channel")
		return
	}

	if !wasAlreadyAssigned {
		//TODO: Ask geard to unidle container
		fmt.Printf("Starting container %v\n", id)
		if err := systemd.Connection().StartUnitJob(id.UnitNameFor(), "fail"); err != nil {
			fmt.Printf("unidle: Could not start container %s: %v", id.UnitNameFor(), err)
			p.SetVerdict(netfilter.NF_ACCEPT)
			return
		}
	}

	p.SetRequeueVerdict(newChanId)
}

func (idler *Idler) getAvailableWaiter(id containers.Identifier) (uint16, bool) {
	for true {
		//existing queue is already processing id
		for i := range idler.openChannels {
			if i != 0 && idler.openChannels[i] == id {
				return uint16(i), true
			}
		}

		for i := range idler.openChannels {
			if i != 0 && (idler.openChannels[i] == "") {
				idler.openChannels[i] = id
				return uint16(i), false
			}
		}

		//Wait for channels to open
		time.Sleep(time.Second)
	}
	return 0, false
}

func (idler *Idler) idleContainer(id containers.Identifier) {
	portPairs, err := containers.GetExistingPorts(id)
	if err != nil {
		fmt.Printf("IDLE: Error retrieving ports for container: %v", id)
		return
	}

	iptablePorts, err := iptables.GetIdlerRules(id)
	if err != nil {
		fmt.Printf("IDLE: Error retrieving ports from iptables: %v", id)
		return
	}

	shouldRecreateRules := false
	for _, portPair := range portPairs {
		extPort := strconv.Itoa(int(portPair.External))
		shouldRecreateRules = shouldRecreateRules || !iptablePorts[extPort]
	}

	if !shouldRecreateRules {
		return
	}

	//TODO: Ask geard to idle container
	fmt.Printf("Stopping container %v\n", id)
	if err := systemd.Connection().StopUnitJob(id.UnitNameFor(), "fail"); err != nil {
		fmt.Printf("idle: Could not stop container %s: %v", id.UnitNameFor(), err)
		return
	}

	iptables.IdleContainer(id, idler.hostIp)
}

func waitStart(pChan <-chan netfilter.NFPacket, chanId uint16, waitChan chan<- uint16, hostIp string) {
	for true {
		p := <-pChan

		id, err := identifierForPacket(p)
		if err != nil {
			fmt.Println(err)
			p.SetVerdict(netfilter.NF_ACCEPT)
			waitChan <- chanId
			continue
		}

		cInfo, err := systemd.Connection().GetUnitProperties(id.UnitNameFor())
		if err != nil || cInfo["ActiveState"] != "active" {
			//TODO: Placeholder for container start detection
			fmt.Println("Waiting for application to start")
			time.Sleep(time.Second * 5)
			fmt.Println("Application started")

			iptables.UnidleContainer(id, hostIp)
		}

		p.SetVerdict(netfilter.NF_ACCEPT)
		waitChan <- chanId
	}
}

func identifierForPacket(p netfilter.NFPacket) (containers.Identifier, error) {
	tcpLayer := p.Packet.TransportLayer()
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return "", fmt.Errorf("Unknown packet of type %v\n", tcpLayer.LayerType())
	}

	//unidle container
	port := containers.Port(tcp.DstPort)
	return port.IdentifierFor()
}
