package opcua

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"net"
	"os"
	"regexp"
	runtime_debug "runtime/debug"
	"sort"
	"time"
)

const (
	UATransportBinary = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
)

var (
	endpointRegex = regexp.MustCompile("^opc\\.tcp://([^:/\\n]+)(?::([0-9]+))?(.*)$")
)

type Flags struct {
	zgrab2.BaseFlags
	CertPath        string
	KeyPath         string
	BrowseTimeout   time.Duration `long:"BrowseTimeout" description:"Timeout in seconds for browsing endpoint nodes"`
	SleepTime       time.Duration `long:"SleepTime" description:"Time to sleep between two consecutive requests"`
	MaxChildren     int           `long:"MaxChildren" description:"Max number of children to request per node"`
	ReadChunkSize   int           `long:"ReadChunkSize" description:"Max number of attributes to read in a single request"`
	BrowseChunkSize int           `long:"BrowseChunkSize" description:"Max number of references to browse per request"`
	Debug           bool          `long:"Debug" description:"Enable debug logging"`
	ProductURI      string        `long:"ProductURI" description:"the product URI shown to remote servers"`
	ApplicationURI  string        `long:"ApplicationURI" description:"the application URI shown to remote servers"`
	ApplicationName string        `long:"ApplicationName" description:"The application name shown to remote servers"`
	DNS             string        `long:"DNS" description:"Address of DNS server to use for resolving the hostname of discovered servers"`
	ReadLimit       int           `long:"ReadLimit" description:"Limit on incoming traffic per target during browse phase"`
	InitialNodes    string        `long:"InitialNodes" description:"comma separated list of node ids to start browsing with"`
}

type Module struct {
}

type Scanner struct {
	config            *Flags
	cert              opcua.Option
	key               opcua.Option
	nodeAttrs         []ua.AttributeID
	nodeSpecificAttrs map[ua.NodeClass][]ua.AttributeID
	resolver          *net.Resolver
	localKey          *rsa.PrivateKey
}

// registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("opcua", "opcua", "Probe for OPC UA handshake", 4840, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// return the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Try the OPC UA handshake and fetch server details if successful."
}

// initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	if f.Debug {
		log.SetLevel(log.DebugLevel)
	}

	// extension objects
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.BuildInfo), new(ua.BuildInfo))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.ServerStatusDataType), new(ua.ServerStatusDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.EndpointType), new(ua.EndpointType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.IdentityMappingRuleType), new(ua.IdentityMappingRuleType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.Range), new(ua.Range))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.RedundantServerDataType), new(ua.RedundantServerDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.SamplingIntervalDiagnosticsDataType), new(ua.SamplingIntervalDiagnosticsDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.RolePermissionType), new(ua.RolePermissionType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.SessionDiagnosticsDataType), new(ua.SessionDiagnosticsDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.NetworkGroupDataType), new(ua.NetworkGroupDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.SessionSecurityDiagnosticsDataType), new(ua.SessionSecurityDiagnosticsDataType))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.MessageSecurityMode), new(ua.MessageSecurityMode))
	ua.RegisterExtensionObject(ua.NewNumericNodeID(0, id.TimeZoneDataType), new(ua.TimeZoneDataType))

	// certificates
	if f.CertPath == "" && f.KeyPath == "" {
		f.CertPath = "cert.pem"
		f.KeyPath = "key.pem"
	}

	if !fileExists(f.CertPath) && !fileExists(f.KeyPath) {
		hostname, err := os.Hostname()
		if err != nil {
			log.Printf("Failed to get hostname: %s", err)
		}
		generate_cert(hostname, 2048, f.CertPath, f.KeyPath)
	}

	c, err := tls.LoadX509KeyPair(f.CertPath, f.KeyPath)
	if err != nil {
		log.Printf("Failed to load certificate: %s", err)
	} else {
		pk, ok := c.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatalf("Invalid private key")
		}
		scanner.cert = opcua.Certificate(c.Certificate[0])
		scanner.key = opcua.PrivateKey(pk)
		scanner.localKey = pk
	}

	// Timeout for browsing
	if scanner.config.BrowseTimeout == 0 {
		scanner.config.BrowseTimeout = 60 * time.Minute
	}
	log.Printf("Configured Browse Timeout is %s", scanner.config.BrowseTimeout.String())

	// Sleeptime
	if scanner.config.SleepTime == 0 {
		scanner.config.SleepTime = 500 * time.Millisecond
	}
	log.Printf("Configured sleep time is %s", scanner.config.SleepTime.String())

	// MaxChildren
	if scanner.config.MaxChildren == 0 {
		scanner.config.MaxChildren = 50
	}
	log.Printf("Configured %d max children per node", scanner.config.MaxChildren)

	// ReadChunkSize
	if scanner.config.ReadChunkSize == 0 {
		scanner.config.ReadChunkSize = 50
	}
	log.Printf("Configured ReadChunkSize is %d", scanner.config.ReadChunkSize)

	// BrowseChunkSize
	if scanner.config.BrowseChunkSize == 0 {
		scanner.config.BrowseChunkSize = 50
	}
	log.Printf("Configured BrowseChunkSize is %d", scanner.config.BrowseChunkSize)

	// ApplicationURI
	if scanner.config.ApplicationURI == "" {
		hostname, err := os.Hostname()
		if err != nil {
			panic(err)
		}
		scanner.config.ApplicationURI = fmt.Sprintf("urn:io.zmap.zgrab2.opcua:%s", hostname)
	}

	// Product URI
	if scanner.config.ProductURI == "" {
		scanner.config.ProductURI = "urn:io.zmap.zgrab2.opcua"
	}

	// ApplicationName
	if scanner.config.ApplicationName == "" {
		scanner.config.ApplicationName = "OPC UA Scanner (zgrab2)"
	}
	log.Printf("Identifying as ApplicationName: '%s' ApplicationURI: '%s' ProductURI: '%s'",
		scanner.config.ApplicationName, scanner.config.ApplicationURI, scanner.config.ProductURI)

	// DNS
	scanner.resolver = &net.Resolver{
		PreferGo: true,
	}
	if f.DNS != "" {
		scanner.resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", f.DNS))
		}
	}

	// ReadLimit
	if f.ReadLimit == 0 {
		scanner.config.ReadLimit = 50
	}

	// Inital nodes
	if f.InitialNodes == "" {
		scanner.config.InitialNodes = "i=2255,i=2256,i=85"
	}

	return err
}

// initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "opcua"
}

func updateByteCounter(conn *zgrab2.TimeoutConnection, ret *Log) {
	ret.BytesRead += conn.BytesRead
	ret.BytesWritten += conn.BytesWritten
}

// probes for a opcua service.
// If the response is not a valid opcua response to this packet, then fail with a SCAN_PROTOCOL_ERROR.
// Otherwise, return the parsed response and status (SCAN_SUCCESS or SCAN_APPLICATION_ERROR)
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	tStart := time.Now()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "host", target.IP.String()))
	cl := contextLogger(ctx)
	resultLog := new(Log)
	defer func() {
		cancel()
		if err := recover(); err != nil {
			contextLogger(ctx).Errorf("Panic during scan: %v", err)
			fmt.Println("stacktrace from panic: \n" + string(runtime_debug.Stack()))
			resultLog.ErrorMsg = fmt.Sprintf("%v", err)
			resultLog.Panic = true
		}
	}()

	if target.Port == nil {
		port := uint(4840)
		target.Port = &port
	}

	t := &uaScanTarget{
		config:    scanner.config,
		scanner:   scanner,
		resultLog: resultLog,
		target:    &target,
	}

	// Grab server description at default port 4840
	resultLog.Endpoints = make([]*ua.EndpointDescription, 0)
	endpointUrl := fmt.Sprintf("opc.tcp://%s:%d", target.Host(), *target.Port)
	err := t.getEndpointsAndServers(ctx, endpointUrl)
	if err != nil {
		cl.Debugf("Could not get endpoints: %s", err.Error())
		return zgrab2.TryGetScanStatus(err), resultLog, err
	}

	// Scan further endpoints discovered using FindServers()
	if resultLog.Servers != nil {
		t.scanServersForEndpoints(ctx, resultLog.Servers)
	}

	availableEndpoints, scannableEndpoints := filterEndpoints(resultLog.Endpoints)

	t.scanEndpointKeyPosession(ctx, availableEndpoints)
	t.scanEndpoints(ctx, scannableEndpoints)

	resultLog.ScanDuration = time.Since(tStart)
	resultLog.NumBrowseReq = t.numBrowseReq
	resultLog.NumReadReq = t.numReadReq
	resultLog.BrowseDuration = t.browseReqDuration
	resultLog.ReadDuration = t.readReqDuration

	addr, dnsErr := scanner.resolver.LookupAddr(ctx, target.IP.String())
	if dnsErr == nil && len(addr) > 0 {
		resultLog.RDNS = addr[0]
	}

	status := zgrab2.SCAN_SUCCESS
	return status, resultLog, err
}

func filterEndpoints(endpoints []*ua.EndpointDescription) (map[string][]*ua.EndpointDescription, map[string][]*ua.EndpointDescription) {
	// endpoints that offer anonymous access, are servers and use binary protocol
	scannableEndpoints := make(map[string][]*ua.EndpointDescription)

	// endpoints that use binary protocol
	availableEndpoints := make(map[string][]*ua.EndpointDescription)

	for _, e := range endpoints {
		if e.TransportProfileURI != UATransportBinary {
			continue
		}
		availableEndpoints[e.EndpointURL] = append(availableEndpoints[e.EndpointURL], e)
		if e.Server.ApplicationType != ua.ApplicationTypeServer &&
			e.Server.ApplicationType != ua.ApplicationTypeClientAndServer {
			continue
		}
		for _, t := range e.UserIdentityTokens {
			if t.TokenType == ua.UserTokenTypeAnonymous {
				scannableEndpoints[e.EndpointURL] = append(scannableEndpoints[e.EndpointURL], e)
			}
		}
	}
	sortEndpointsMap(availableEndpoints)
	sortEndpointsMap(scannableEndpoints)
	return availableEndpoints, scannableEndpoints
}

func sortEndpointsMap(e map[string][]*ua.EndpointDescription) {
	for _, list := range e {
		sort.SliceStable(list, func(i, j int) bool {
			secModeDiff := list[i].SecurityMode - list[j].SecurityMode
			if secModeDiff != 0 {
				return secModeDiff > 0
			}
			return list[i].SecurityLevel > list[j].SecurityLevel
		})
	}
}

func normalizeEndpointURL(uri string) string {
	// normalize endpoint url in case that port is missing
	match := endpointRegex.FindStringSubmatch(uri)
	port := match[2]
	if port == "" {
		port = "4840"
	}
	return fmt.Sprintf("opc.tcp://%s:%s%s", match[1], port, match[3])
}

func contextLogger(ctx context.Context) *log.Entry {
	cl := log.WithContext(ctx)
	if ctxHost, ok := ctx.Value("host").(string); ok {
		cl = cl.WithField("host", ctxHost)
	}
	if ctxEndpoint, ok := ctx.Value("endpoint").(string); ok {
		cl = cl.WithField("endpoint", ctxEndpoint)
	}
	return cl
}
