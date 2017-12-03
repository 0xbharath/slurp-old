package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CaliDog/certstream-go"
	"github.com/joeguo/tldextract"

	log "github.com/Sirupsen/logrus"
	"github.com/Workiva/go-datastructures/queue"
)

var exit bool
var dQ *queue.Queue
var dbQ *queue.Queue
var permutatedQ *queue.Queue
var extract *tldextract.TLDExtract
var checked int64

var action string

type Domain struct {
	CN     string
	Domain string
	Suffix string
}

type PermutatedDomain struct {
	Permutation string
	Domain      Domain
}

var rootCmd = &cobra.Command{
	Use:   "slurp",
	Short: "slurp",
	Long:  `slurp`,
	Run: func(cmd *cobra.Command, args []string) {
		action = "NADA"
	},
}

var certstreamCmd = &cobra.Command{
	Use:   "certstream",
	Short: "Uses certstream to find s3 buckets in real-time",
	Long:  "Uses certstream to find s3 buckets in real-time",
	Run: func(cmd *cobra.Command, args []string) {
		action = "CERTSTREAM"
	},
}

var manualCmd = &cobra.Command{
	Use:   "domain",
	Short: "Takes a domain as input and attempts to find its s3 buckets",
	Long:  "Takes a domain as input and attempts to find its s3 buckets",
	Run: func(cmd *cobra.Command, args []string) {
		action = "MANUAL"
	},
}

var (
	cfgDomain string
)

func setFlags() {
	manualCmd.PersistentFlags().StringVar(&cfgDomain, "domain", "", "Domain to enumerate s3 bucks with")
}

// PreInit initializes goroutine concurrency and initializes cobra
func PreInit() {
	setFlags()

	helpCmd := rootCmd.HelpFunc()

	var helpFlag bool

	newHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpCmd(c, args)
	}
	rootCmd.SetHelpFunc(newHelpCmd)

	// certstreamCmd command help
	helpCertstreamCmd := certstreamCmd.HelpFunc()
	newCertstreamHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpCertstreamCmd(c, args)
	}
	certstreamCmd.SetHelpFunc(newCertstreamHelpCmd)

	// manualCmd command help
	helpManualCmd := manualCmd.HelpFunc()
	newManualHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpManualCmd(c, args)
	}
	manualCmd.SetHelpFunc(newManualHelpCmd)

	// Add subcommands
	rootCmd.AddCommand(certstreamCmd)
	rootCmd.AddCommand(manualCmd)

	err := rootCmd.Execute()

	if err != nil {
		log.Fatal(err)
	}

	if helpFlag {
		os.Exit(0)
	}
}

// StreamCerts takes input from certstream and stores it in the queue
func StreamCerts() {
	// The false flag specifies that we don't want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	for {
		select {
		case jq := <-stream:
			domain, err2 := jq.String("data", "leaf_cert", "subject", "CN")

			if err2 != nil {
				if !strings.Contains(err2.Error(), "Error decoding jq string") {
					continue
				}
				log.Error(err2)
			}

			//log.Infof("Domain: %s", domain)
			//log.Info(jq)

			dQ.Put(domain)

		case err := <-errStream:
			log.Error(err)
		}
	}
}

// ProcessQueue processes data stored in the queue
func ProcessQueue() {
	for {
		cn, err := dQ.Get(1)

		if err != nil {
			log.Error(err)
			continue
		}

		//log.Infof("Domain: %s", cn[0].(string))

		if !strings.Contains(cn[0].(string), "cloudflaressl") && !strings.Contains(cn[0].(string), "xn--") && len(cn[0].(string)) > 0 && !strings.HasPrefix(cn[0].(string), "*.") {
			result := extract.Extract(cn[0].(string))
			//domain := fmt.Sprintf("%s.%s", result.Root, result.Tld)

			d := Domain{
				CN:     cn[0].(string),
				Domain: result.Root,
				Suffix: result.Tld,
			}

			dbQ.Put(d)
		}

		//log.Infof("CN: %s\tDomain: %s", cn[0].(string), domain)
	}
}

// StoreInDB stores the dbQ results into the database
func StoreInDB() {
	for {
		dstruct, err := dbQ.Get(1)

		if err != nil {
			log.Error(err)
			continue
		}

		var d Domain = dstruct[0].(Domain)

		//log.Infof("CN: %s\tDomain: %s.%s", d.CN, d.Domain, d.Suffix)

		pd := PermutateDomain(d.Domain, d.Suffix)

		for p := range pd {
			permutatedQ.Put(PermutatedDomain{
				Permutation: pd[p],
				Domain:      d,
			})
		}
	}
}

func CheckPermutations() {
	var max = runtime.NumCPU() * runtime.NumCPU()
	sem := make(chan int, max)

	for {
		sem <- 1
		dom, err := permutatedQ.Get(1)

		if err != nil {
			log.Error(err)
		}

		go func(pd PermutatedDomain) {
			tr := &http.Transport{
				IdleConnTimeout:       3 * time.Second,
				ResponseHeaderTimeout: 3 * time.Second,
			}
			client := &http.Client{
				Transport: tr,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			req, err := http.NewRequest("GET", "http://s3-1-w.amazonaws.com", nil)

			if err != nil {
				if !strings.Contains(err.Error(), "timeout") {
					log.Error(err)
				}

				permutatedQ.Put(pd)
				<-sem
				return
			}

			req.Host = pd.Permutation
			//req.Header.Add("Host", host)

			resp, err1 := client.Do(req)

			if err1 != nil {
				log.Error(err1)
				permutatedQ.Put(pd)
				<-sem
				return
			}

			defer resp.Body.Close()

			//log.Infof("%s (%d)", host, resp.StatusCode)

			if resp.StatusCode == 307 {
				loc := resp.Header.Get("Location")

				req, err := http.NewRequest("GET", loc, nil)

				if err != nil {
					log.Error(err)
				}

				resp, err1 := client.Do(req)

				if err1 != nil {
					if !strings.Contains(err1.Error(), "timeout") {
						log.Error(err1)
					}
				}

				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					log.Infof("PUBLIC: %s (http://%s.%s)", pd.Domain.Domain, pd.Domain.Suffix)
				} else if resp.StatusCode == 403 {
					log.Infof("FORBIDDEN: http://%s (http://%s.%s)", pd.Permutation, pd.Domain.Domain, pd.Domain.Suffix)
				}
			} else if resp.StatusCode == 403 {
				log.Infof("FORBIDDEN: http://%s (http://%s.%s)", pd.Permutation, pd.Domain.Domain, pd.Domain.Suffix)
			} else if resp.StatusCode == 503 {
				log.Info("too fast")
				permutatedQ.Put(pd)
			}

			checked = checked + 1

			<-sem
		}(dom[0].(PermutatedDomain))
	}
}

// PermutateDomain returns all possible domain permutations
func PermutateDomain(domain, suffix string) []string {
	s3url := "s3.amazonaws.com"

	return []string{
		fmt.Sprintf("%s.%s", domain, s3url),
		fmt.Sprintf("www-%s.%s", domain, s3url),
		fmt.Sprintf("%s-www.%s", domain, s3url),
		fmt.Sprintf("%s-backup.%s", domain, s3url),
		fmt.Sprintf("backup-%s.%s", domain, s3url),
		fmt.Sprintf("%s-bak.%s", domain, s3url),
		fmt.Sprintf("bak-%s.%s", domain, s3url),
		fmt.Sprintf("%s-dev.%s", domain, s3url),
		fmt.Sprintf("dev-%s.%s", domain, s3url),
		fmt.Sprintf("%s-staging.%s", domain, s3url),
		fmt.Sprintf("staging-%s.%s", domain, s3url),
		fmt.Sprintf("%s-stage.%s", domain, s3url),
		fmt.Sprintf("stage-%s.%s", domain, s3url),
		fmt.Sprintf("%s-test.%s", domain, s3url),
		fmt.Sprintf("test-%s.%s", domain, s3url),
		fmt.Sprintf("%s-testing.%s", domain, s3url),
		fmt.Sprintf("testing-%s.%s", domain, s3url),
		fmt.Sprintf("%s-billing.%s", domain, s3url),
		fmt.Sprintf("billing-%s.%s", domain, s3url),
		fmt.Sprintf("%s-infra.%s", domain, s3url),
		fmt.Sprintf("infra-%s.%s", domain, s3url),
		fmt.Sprintf("%s-internal.%s", domain, s3url),
		fmt.Sprintf("internal-%s.%s", domain, s3url),
		fmt.Sprintf("%s-tools.%s", domain, s3url),
		fmt.Sprintf("tools-%s.%s", domain, s3url),
		fmt.Sprintf("%s-ops.%s", domain, s3url),
		fmt.Sprintf("ops-%s.%s", domain, s3url),
		fmt.Sprintf("%s.%s.%s", domain, suffix, s3url),
		fmt.Sprintf("%s-builds.%s", domain, s3url),
		fmt.Sprintf("builds-%s.%s", domain, s3url),
		fmt.Sprintf("%s-downloads.%s", domain, s3url),
		fmt.Sprintf("downloads-%s.%s", domain, s3url),
		fmt.Sprintf("%s-services.%s", domain, s3url),
		fmt.Sprintf("services-%s.%s", domain, s3url),
		fmt.Sprintf("%s-logs.%s", domain, s3url),
		fmt.Sprintf("logs-%s.%s", domain, s3url),
		fmt.Sprintf("%s-cloudformation.%s", domain, s3url),
		fmt.Sprintf("cloudformation-%s.%s", domain, s3url),
		fmt.Sprintf("%s-cf.%s", domain, s3url),
		fmt.Sprintf("cf-%s.%s", domain, s3url),
		fmt.Sprintf("%s-lambda.%s", domain, s3url),
		fmt.Sprintf("lambda-%s.%s", domain, s3url),
		fmt.Sprintf("%s-support.%s", domain, s3url),
		fmt.Sprintf("support-%s.%s", domain, s3url),
		fmt.Sprintf("%s-public.%s", domain, s3url),
		fmt.Sprintf("public-%s.%s", domain, s3url),
		fmt.Sprintf("%s-cache.%s", domain, s3url),
		fmt.Sprintf("cache-%s.%s", domain, s3url),
		fmt.Sprintf("%s-artifacts.%s", domain, s3url),
		fmt.Sprintf("artifacts-%s.%s", domain, s3url),
		fmt.Sprintf("%s-internal-tools.%s", domain, s3url),
		fmt.Sprintf("internal-tools-%s.%s", domain, s3url),
		fmt.Sprintf("%s-mail.%s", domain, s3url),
		fmt.Sprintf("mail-%s.%s", domain, s3url),
		fmt.Sprintf("%s-reports.%s", domain, s3url),
		fmt.Sprintf("reports-%s.%s", domain, s3url),
		fmt.Sprintf("%s-packages.%s", domain, s3url),
		fmt.Sprintf("packages-%s.%s", domain, s3url),
		fmt.Sprintf("%s-snapshot.%s", domain, s3url),
		fmt.Sprintf("snapshot-%s.%s", domain, s3url),
		fmt.Sprintf("%s-iam.%s", domain, s3url),
		fmt.Sprintf("iam-%s.%s", domain, s3url),
		fmt.Sprintf("%s-templates.%s", domain, s3url),
		fmt.Sprintf("templates-%s.%s", domain, s3url),
		fmt.Sprintf("%s-ec2.%s", domain, s3url),
		fmt.Sprintf("ec2-%s.%s", domain, s3url),
		fmt.Sprintf("%s-s3.%s", domain, s3url),
		fmt.Sprintf("s3-%s.%s", domain, s3url),
		fmt.Sprintf("%s-rds.%s", domain, s3url),
		fmt.Sprintf("rds-%s.%s", domain, s3url),
		fmt.Sprintf("%s-elb.%s", domain, s3url),
		fmt.Sprintf("elb-%s.%s", domain, s3url),
		fmt.Sprintf("%s-dynamo.%s", domain, s3url),
		fmt.Sprintf("dynamo-%s.%s", domain, s3url),
		fmt.Sprintf("%s-dynamodb.%s", domain, s3url),
		fmt.Sprintf("dynamodb-%s.%s", domain, s3url),
		fmt.Sprintf("%s-mysql.%s", domain, s3url),
		fmt.Sprintf("mysql-%s.%s", domain, s3url),
		fmt.Sprintf("%s-psql.%s", domain, s3url),
		fmt.Sprintf("psql-%s.%s", domain, s3url),
		fmt.Sprintf("%s-postgres.%s", domain, s3url),
		fmt.Sprintf("postgres-%s.%s", domain, s3url),
		fmt.Sprintf("%s-ldap.%s", domain, s3url),
		fmt.Sprintf("ldap-%s.%s", domain, s3url),
		fmt.Sprintf("%s-oracle.%s", domain, s3url),
		fmt.Sprintf("oracle-%s.%s", domain, s3url),
		fmt.Sprintf("%s-common.%s", domain, s3url),
		fmt.Sprintf("common-%s.%s", domain, s3url),
		fmt.Sprintf("%s-dns.%s", domain, s3url),
		fmt.Sprintf("dns-%s.%s", domain, s3url),
		fmt.Sprintf("%s-sec.%s", domain, s3url),
		fmt.Sprintf("sec-%s.%s", domain, s3url),
		fmt.Sprintf("%s-security.%s", domain, s3url),
		fmt.Sprintf("security-%s.%s", domain, s3url),
		fmt.Sprintf("%s-audit.%s", domain, s3url),
		fmt.Sprintf("audit-%s.%s", domain, s3url),
		fmt.Sprintf("%s-audit-logs.%s", domain, s3url),
		fmt.Sprintf("audit-logs-%s.%s", domain, s3url),
		fmt.Sprintf("%s-graphql.%s", domain, s3url),
		fmt.Sprintf("graphql-%s.%s", domain, s3url),
		fmt.Sprintf("%s-terraform.%s", domain, s3url),
		fmt.Sprintf("terraform-%s.%s", domain, s3url),
		fmt.Sprintf("%s-troposphere.%s", domain, s3url),
		fmt.Sprintf("troposphere-%s.%s", domain, s3url),
		fmt.Sprintf("%s-help.%s", domain, s3url),
		fmt.Sprintf("help-%s.%s", domain, s3url),
		fmt.Sprintf("%s-uploads.%s", domain, s3url),
		fmt.Sprintf("uploads-%s.%s", domain, s3url),
		fmt.Sprintf("%s-media.%s", domain, s3url),
		fmt.Sprintf("media-%s.%s", domain, s3url),
		fmt.Sprintf("%s-share.%s", domain, s3url),
		fmt.Sprintf("share-%s.%s", domain, s3url),
		fmt.Sprintf("%s-consultants.%s", domain, s3url),
		fmt.Sprintf("consultants-%s.%s", domain, s3url),
		fmt.Sprintf("%s-loadbalancer.%s", domain, s3url),
		fmt.Sprintf("loadbalancer-%s.%s", domain, s3url),
		fmt.Sprintf("%s-ios.%s", domain, s3url),
		fmt.Sprintf("ios-%s.%s", domain, s3url),
		fmt.Sprintf("%s-android.%s", domain, s3url),
		fmt.Sprintf("android-%s.%s", domain, s3url),
		fmt.Sprintf("%s-git.%s", domain, s3url),
		fmt.Sprintf("git-%s.%s", domain, s3url),
		fmt.Sprintf("%s-svn.%s", domain, s3url),
		fmt.Sprintf("svn-%s.%s", domain, s3url),
		fmt.Sprintf("%s-gcp.%s", domain, s3url),
		fmt.Sprintf("gcp-%s.%s", domain, s3url),
		fmt.Sprintf("%s-aws.%s", domain, s3url),
		fmt.Sprintf("aws-%s.%s", domain, s3url),
		fmt.Sprintf("%s-subversion.%s", domain, s3url),
		fmt.Sprintf("subversion-%s.%s", domain, s3url),
		fmt.Sprintf("%s-mercurial.%s", domain, s3url),
		fmt.Sprintf("mercurial-%s.%s", domain, s3url),
		fmt.Sprintf("%s-teamcity.%s", domain, s3url),
		fmt.Sprintf("teamcity-%s.%s", domain, s3url),
		fmt.Sprintf("%s-jira.%s", domain, s3url),
		fmt.Sprintf("jira-%s.%s", domain, s3url),
		fmt.Sprintf("%s-splunk.%s", domain, s3url),
		fmt.Sprintf("splunk-%s.%s", domain, s3url),
		fmt.Sprintf("%s-elastic.%s", domain, s3url),
		fmt.Sprintf("elastic-%s.%s", domain, s3url),
		fmt.Sprintf("%s-es.%s", domain, s3url),
		fmt.Sprintf("es-%s.%s", domain, s3url),
		fmt.Sprintf("%s-elk.%s", domain, s3url),
		fmt.Sprintf("elk-%s.%s", domain, s3url),
		fmt.Sprintf("%s-logstash.%s", domain, s3url),
		fmt.Sprintf("logstash-%s.%s", domain, s3url),
		fmt.Sprintf("%s-betas.%s", domain, s3url),
		fmt.Sprintf("betas-%s.%s", domain, s3url),
		fmt.Sprintf("%s-corporate.%s", domain, s3url),
		fmt.Sprintf("corporate-%s.%s", domain, s3url),
		fmt.Sprintf("%s-developer.%s", domain, s3url),
		fmt.Sprintf("developer-%s.%s", domain, s3url),
		fmt.Sprintf("%s-developers.%s", domain, s3url),
		fmt.Sprintf("developers-%s.%s", domain, s3url),
		fmt.Sprintf("%s-cluster.%s", domain, s3url),
		fmt.Sprintf("cluster-%s.%s", domain, s3url),
		fmt.Sprintf("%s-club.%s", domain, s3url),
		fmt.Sprintf("club-%s.%s", domain, s3url),
		fmt.Sprintf("%s-training.%s", domain, s3url),
		fmt.Sprintf("training-%s.%s", domain, s3url),
		fmt.Sprintf("%s-project.%s", domain, s3url),
		fmt.Sprintf("project-%s.%s", domain, s3url),
		fmt.Sprintf("%s-projects.%s", domain, s3url),
		fmt.Sprintf("projects-%s.%s", domain, s3url),
		fmt.Sprintf("%s-stats.%s", domain, s3url),
		fmt.Sprintf("stats-%s.%s", domain, s3url),
		fmt.Sprintf("%s-bucket.%s", domain, s3url),
		fmt.Sprintf("bucket-%s.%s", domain, s3url),
		fmt.Sprintf("%s-tmp.%s", domain, s3url),
		fmt.Sprintf("tmp-%s.%s", domain, s3url),
		fmt.Sprintf("%s-temp.%s", domain, s3url),
		fmt.Sprintf("temp-%s.%s", domain, s3url),
		fmt.Sprintf("%s-admin.%s", domain, s3url),
		fmt.Sprintf("admin-%s.%s", domain, s3url),
		fmt.Sprintf("%s-devops.%s", domain, s3url),
		fmt.Sprintf("devops-%s.%s", domain, s3url),
		fmt.Sprintf("%s-bamboo.%s", domain, s3url),
		fmt.Sprintf("bamboo-%s.%s", domain, s3url),
		fmt.Sprintf("%s-travis.%s", domain, s3url),
		fmt.Sprintf("travis-%s.%s", domain, s3url),
		fmt.Sprintf("%s-docker.%s", domain, s3url),
		fmt.Sprintf("docker-%s.%s", domain, s3url),
		fmt.Sprintf("%s-ecs.%s", domain, s3url),
		fmt.Sprintf("ecs-%s.%s", domain, s3url),
		fmt.Sprintf("%s-kubernetes.%s", domain, s3url),
		fmt.Sprintf("kubernetes-%s.%s", domain, s3url),
		fmt.Sprintf("%s-data.%s", domain, s3url),
		fmt.Sprintf("data-%s.%s", domain, s3url),
		fmt.Sprintf("%s-traffic.%s", domain, s3url),
		fmt.Sprintf("traffic-%s.%s", domain, s3url),
		fmt.Sprintf("%s-graphite.%s", domain, s3url),
		fmt.Sprintf("graphite-%s.%s", domain, s3url),
		fmt.Sprintf("%s-awslogs.%s", domain, s3url),
		fmt.Sprintf("awslogs-%s.%s", domain, s3url),
		fmt.Sprintf("%s-syslog.%s", domain, s3url),
		fmt.Sprintf("syslog-%s.%s", domain, s3url),
		fmt.Sprintf("%s-aws-logs.%s", domain, s3url),
		fmt.Sprintf("aws-logs-%s.%s", domain, s3url),
		fmt.Sprintf("%s-github.%s", domain, s3url),
		fmt.Sprintf("github-%s.%s", domain, s3url),
		fmt.Sprintf("%s-gitlab.%s", domain, s3url),
		fmt.Sprintf("gitlab-%s.%s", domain, s3url),
		fmt.Sprintf("%s-src.%s", domain, s3url),
		fmt.Sprintf("src-%s.%s", domain, s3url),
		fmt.Sprintf("%s-source.%s", domain, s3url),
		fmt.Sprintf("source-%s.%s", domain, s3url),
		fmt.Sprintf("%s-scripts.%s", domain, s3url),
		fmt.Sprintf("scripts-%s.%s", domain, s3url),
		fmt.Sprintf("%s.%s", strings.Replace(fmt.Sprintf("%s.%s", domain, suffix), ".", "", -1), s3url),
	}
}

// Init does low level initialization before we can run
func Init() {
	var err error

	dQ = queue.New(1000)

	dbQ = queue.New(1000)

	permutatedQ = queue.New(1000)

	extract, err = tldextract.New("./tld.cache", false)

	if err != nil {
		log.Fatal(err)
	}
}

func PrintJob() {
	for {
		log.Infof("dQ size: %d", dQ.Len())
		log.Infof("dbQ size: %d", dbQ.Len())
		log.Infof("permutatedQ size: %d", permutatedQ.Len())
		log.Infof("Checked: %d", checked)

		time.Sleep(10 * time.Second)
	}
}

func main() {
	PreInit()

	switch action {
	case "CERTSTREAM":
		log.Info("Initializing....")
		Init()

		//go PrintJob()

		log.Info("Starting to stream certs....")
		go StreamCerts()

		log.Info("Starting to process queue....")
		go ProcessQueue()

		//log.Info("Starting to stream certs....")
		go StoreInDB()

		log.Info("Starting to process permutations....")
		go CheckPermutations()

		for {
			if exit {
				break
			}

			time.Sleep(1 * time.Second)
		}
	case "MANUAL":
		if cfgDomain == "" {
			log.Fatal("You must specify a domain to enumerate")
		}

		Init()

		result := extract.Extract(cfgDomain)

		if result.Root == "" || result.Tld == "" {
			log.Fatal("Is the domain even valid bruh?")
		}

		d := Domain{
			CN:     cfgDomain,
			Domain: result.Root,
			Suffix: result.Tld,
		}

		dbQ.Put(d)

		log.Info("Starting to process queue....")
		go ProcessQueue()

		//log.Info("Starting to stream certs....")
		go StoreInDB()

		log.Info("Starting to process permutations....")
		go CheckPermutations()

		for {
			if exit {
				break
			}

			if permutatedQ.Len() == 0 || dbQ.Len() > 0 {
				exit = true
			}

			time.Sleep(1 * time.Second)
		}

	case "NADA":
		log.Info("Check help")
		os.Exit(0)
	}
}
