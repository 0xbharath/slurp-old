package main

import (
	"time"

	"github.com/CaliDog/certstream-go"

	log "github.com/Sirupsen/logrus"
	"github.com/Workiva/go-datastructures/queue"
)

var exit bool

var dQ *queue.Queue

func StreamCerts() {
	// The false flag specifies that we don't want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	for {
		select {
		case jq := <-stream:
			domain, err2 := jq.String("data", "leaf_cert", "subject", "CN")

			if err2 != nil {
				log.Error("Error decoding jq string")
				continue
			}

			//log.Infof("Domain: %s", domain)
			//log.Info(jq)

			dQ.Put(domain)

		case err := <-errStream:
			log.Error(err)
		}
	}
}

func ProcessQueue() {
	for {
		log.Infof("Queue size: %d", dQ.Len())

		domain, err := dQ.Get(1)

		if err != nil {
			log.Error(err)
			continue
		}

		log.Infof("Domain: %s", domain[0].(string))

	}
}

func Init() {
	dQ = queue.New(1000)
}

func main() {
	Init()

	go ProcessQueue()
	go StreamCerts()

	for {
		if exit {
			break
		}

		time.Sleep(1 * time.Second)
	}
}
