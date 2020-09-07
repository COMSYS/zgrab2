package opcua

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/gopcua/opcua/uasc"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/opcua/browser"
	"net"
	"strings"
	"time"
)

type uaScanTarget struct {
	config            *Flags
	scanner           *Scanner
	target            *zgrab2.ScanTarget
	resultLog         *Log
	numReadReq        uint64
	numBrowseReq      uint64
	readReqDuration   time.Duration
	browseReqDuration time.Duration
}

func (t *uaScanTarget) scanServersForEndpoints(ctx context.Context, targetServers []*ua.ApplicationDescription) {
	cl := contextLogger(ctx)
	for _, server := range targetServers {
	ServerLoop:
		for _, uri := range server.DiscoveryURLs {
			if strings.HasPrefix(uri, "opc.tcp://") {
				normalizedUrl := normalizeEndpointURL(uri)
				for _, existing := range t.resultLog.Endpoints {
					if normalizedUrl == existing.EndpointURL {
						break ServerLoop
					}
				}
				err := t.getEndpointsAndServers(ctx, uri)
				if err != nil {
					cl.Errorf("Could not get endpoints from additional server %s: %s", uri, err.Error())
				}
			}
		}
	}
}

func (t *uaScanTarget) scanEndpoints(ctx context.Context, scannableEndpoints map[string][]*ua.EndpointDescription) {
	t.resultLog.EndpointNodes = make(map[string][]browser.NodeDef)
	t.resultLog.EndpointSecUsed = make(map[string]EndpointSecurity)
	for endpointUrl, list := range scannableEndpoints {
		var certErr ua.StatusCode
		// first: try endpoint with highest security
		endpoint := list[len(list)-1]
		err := t.scanSingleEndpoint(ctx, endpoint)
		if err != nil {
			switch err.(type) {
			case ua.StatusCode:
				certErr = err.(ua.StatusCode)
			case *uacp.Error:
				certErr = ua.StatusCode(err.(*uacp.Error).ErrorCode)
			}
			// if highest security level does not work: retry with lowest
			if err != context.DeadlineExceeded && len(list) > 1 && list[0].SecurityMode == ua.MessageSecurityModeNone {
				endpoint = list[0]
				err = t.scanSingleEndpoint(ctx, endpoint)
				if err != nil {
					t.resultLog.ScanStatus = UAErrorDesc(err)
					t.resultLog.AbortStage = "scan-endpoint-with-none-security"
				}
			} else {
				t.resultLog.ScanStatus = UAErrorDesc(err)
				t.resultLog.AbortStage = "scan-endpoint"
			}
		}
		t.resultLog.EndpointSecUsed[endpointUrl] = EndpointSecurity{
			SecurityMode:      endpoint.SecurityMode,
			SecurityLevel:     endpoint.SecurityLevel,
			SecurityPolicyURI: endpoint.SecurityPolicyURI,
			CertificateError:  UAErrorDesc(certErr),
		}
	}
}

func (t *uaScanTarget) scanSingleEndpoint(ctx context.Context, endpointDesc *ua.EndpointDescription) error {
	ctx = context.WithValue(ctx, "endpoint", endpointDesc.EndpointURL)
	cl := contextLogger(ctx)
	// Pick endpoint with highest security mode
	endpointUrl := endpointDesc.EndpointURL
	cl.Debug("Scanning endpoint")

	// Establish new connection
	updatedFlags := t.config.BaseFlags
	updatedFlags.Timeout = t.config.BrowseTimeout
	updatedFlags.BytesReadLimit = t.config.ReadLimit * 1024 * 1024 //50MB in bytes

	conn, err := t.openConnectionForEndpoint(endpointUrl, updatedFlags)
	if err != nil {
		return err
	}
	defer func() {
		if conn != nil {
			updateByteCounter(conn.(*zgrab2.TimeoutConnection), t.resultLog)
		}
	}()
	c, err := uacp.Wrap(conn, endpointDesc.EndpointURL)
	if err != nil {
		cl.Errorf("Unable to wrap client connection: %s", err.Error())
		_ = conn.Close()
		return err
	}

	// Create OPCUA client
	opts := configureClient(endpointDesc, t.config)
	if endpointDesc.SecurityMode > ua.MessageSecurityModeNone {
		opts = append(opts, t.scanner.cert, t.scanner.key)
	}
	endpointClient := opcua.NewClient(endpointUrl, opts...)

	// Inject zgrab2 connection
	ctx, cancel := context.WithCancel(ctx)
	if err := endpointClient.Wrap(ctx, c); err != nil {
		return err
	}
	defer func() {
		cancel()
		endpointClient.Close()
	}()

	// Get nodes for endpoint
	if err := t.getNodes(ctx, endpointClient, endpointUrl); err != nil {
		cl.Errorf("error while reading nodes: %s", err.Error())
		t.resultLog.Incomplete = true
	}
	return nil
}

func configureClient(endpointDesc *ua.EndpointDescription, f *Flags) []opcua.Option {
	var opts = make([]opcua.Option, 4, 6)
	opts[0] = opcua.ApplicationURI(f.ApplicationURI)
	opts[1] = opcua.ProductURI(f.ProductURI)
	opts[2] = opcua.ApplicationName(f.ApplicationName)
	opts[3] = opcua.SecurityFromEndpoint(endpointDesc, ua.UserTokenTypeAnonymous)
	return opts
}

func (t *uaScanTarget) getNodes(ctx context.Context, c *opcua.Client, endpointUrl string) error {
	browse := browser.UABrowse{
		Client:          c,
		SleepTime:       t.config.SleepTime,
		MaxChildren:     t.config.MaxChildren,
		ReadChunkSize:   t.config.ReadChunkSize,
		BrowseChunkSize: t.config.BrowseChunkSize,
		Nodes:           make(map[string]*browser.NodeDef),
		Host:            t.target.Host(),
		InitialNodeIds:  t.config.InitialNodes,
	}
	err := browse.BrowseBFS(ctx)

	t.resultLog.EndpointNodes[endpointUrl] = make([]browser.NodeDef, 0, len(browse.Nodes))
	for _, n := range browse.Nodes {
		t.resultLog.EndpointNodes[endpointUrl] = append(t.resultLog.EndpointNodes[endpointUrl], *n)
	}
	t.numBrowseReq += browse.NumBrowseReq
	t.numReadReq += browse.NumReadReq
	t.browseReqDuration += browse.BrowseReqDuration
	t.readReqDuration += browse.ReadReqDuration
	return err
}

func (t *uaScanTarget) scanEndpointKeyPosession(ctx context.Context, availableEndpoints map[string][]*ua.EndpointDescription) {
	t.resultLog.EndpointCertificateTest = make(map[string]*string)
	for endpointUrl, list := range availableEndpoints {
		result := "No secure endpoint"
		for _, endpoint := range filterCryptoEndpoints(list) {
			if err := validateRemoteCert(endpoint, t.scanner.localKey); err != nil {
				result = err.Error()
				continue
			}

			//All local checks passed, now try to connect to endpoint
			if certErr := t.testPrivateKeyPossession(ctx, endpoint); certErr != nil {
				switch certErr.(type) {
				case ua.StatusCode:
					result = StatusCodeString(certErr.(ua.StatusCode))
				case *uacp.Error:
					result = StatusCodeString(ua.StatusCode(certErr.(*uacp.Error).ErrorCode))
				default:
					result = certErr.Error()
				}
				break
			}
			result = "OK"
			break
		}
		t.resultLog.EndpointCertificateTest[endpointUrl] = &result
	}
}

func validateRemoteCert(endpoint *ua.EndpointDescription, localKey *rsa.PrivateKey) error {
	var remoteKey *rsa.PublicKey
	remoteCert, err := x509.ParseCertificate(endpoint.ServerCertificate)
	if err != nil {
		return err
	}
	remoteKey, ok := remoteCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("Invalid certificate")
	}
	if _, err = uapolicy.Asymmetric(endpoint.SecurityPolicyURI, localKey, remoteKey); err != nil {
		return err
	}
	return nil
}

func filterCryptoEndpoints(list []*ua.EndpointDescription) []*ua.EndpointDescription {
	cryptoEnabledEndpoints := make([]*ua.EndpointDescription, 0)
	for _, endpointDescription := range list {
		if endpointDescription.SecurityMode == ua.MessageSecurityModeSign || endpointDescription.SecurityMode == ua.MessageSecurityModeSignAndEncrypt {
			cryptoEnabledEndpoints = append(cryptoEnabledEndpoints, endpointDescription)
		}
	}
	return cryptoEnabledEndpoints
}

func (t *uaScanTarget) testPrivateKeyPossession(ctx context.Context, endpointDesc *ua.EndpointDescription) error {
	cl := contextLogger(ctx)
	conn, err := t.openConnectionForEndpoint(endpointDesc.EndpointURL, t.config.BaseFlags)
	if err != nil {
		return err
	}
	defer func() {
		if conn != nil {
			updateByteCounter(conn.(*zgrab2.TimeoutConnection), t.resultLog)
		}
	}()
	c, err := uacp.Wrap(conn, endpointDesc.EndpointURL)
	if err != nil {
		cl.Errorf("Unable to wrap client connection: %v", err)
		_ = conn.Close()
		return err
	}

	// Create OPCUA client
	opts := configureClient(endpointDesc, t.config)
	opts = append(opts, t.scanner.cert, t.scanner.key)
	endpointClient := opcua.NewClient(endpointDesc.EndpointURL, opts...)

	// Inject zgrab2 connection, OpenSecureChannel
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := endpointClient.Wrap(ctx, c); err != nil {
		_ = c.Close()
		return err
	}
	_ = endpointClient.Close()
	return nil
}

func (t *uaScanTarget) getEndpointsAndServers(ctx context.Context, endpointUrl string) error {
	cl := contextLogger(ctx)
	conn, err := t.openConnectionForEndpoint(endpointUrl, t.config.BaseFlags)
	if err != nil {
		return err
	}
	scCfg := opcua.DefaultClientConfig()

	//Hand over zgrab connection to gopcua stack + handshake
	client, err := uacp.Wrap(conn, endpointUrl)
	if client != nil {
		defer func() {
			updateByteCounter(conn.(*zgrab2.TimeoutConnection), t.resultLog)
			if client != nil {
				_ = client.Close()
			}
		}()
	}
	if err != nil {
		t.resultLog.ScanStatus = UAErrorDesc(err)
		t.resultLog.AbortStage = "handshake"
		return err
	}
	t.resultLog.IsOpcUa = true

	// create communication channel for get endpoints request
	sc, err := uasc.NewSecureChannel(endpointUrl, client, scCfg)
	if err != nil {
		t.resultLog.ScanStatus = UAErrorDesc(err)
		t.resultLog.AbortStage = "create-secure-channel"
		return err
	}

	// Start response handler
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go monitorChannel(ctx, sc)
	// open communication channel
	if err := sc.Open(); err != nil {
		t.resultLog.ScanStatus = UAErrorDesc(err)
		t.resultLog.AbortStage = "open-secure-channel"
		return err
	}
	defer func() {
		_ = sc.Close()
	}()

	// Request list of endpoints
	endpointsReq := &ua.GetEndpointsRequest{}
	var endpointsResp *ua.GetEndpointsResponse
	err = sc.SendRequest(endpointsReq, nil, func(v interface{}) error {
		return safeAssign(v, &endpointsResp)
	})
	if err != nil {
		t.resultLog.ScanStatus = UAErrorDesc(err)
		t.resultLog.AbortStage = "get-endpoints"
		return err
	}
	t.resultLog.Endpoints = append(t.resultLog.Endpoints, endpointsResp.Endpoints...)

	// Request list of servers
	findServersReq := &ua.FindServersRequest{}
	var findServersResp *ua.FindServersResponse
	err = sc.SendRequest(findServersReq, nil, func(v interface{}) error {
		return safeAssign(v, &findServersResp)
	})
	if err != nil {
		cl.Infof("FindServers failed: %s", err.Error())
		return nil
	}
	t.resultLog.Servers = findServersResp.Servers
	return nil
}

func (t *uaScanTarget) openConnectionForEndpoint(endpointUrl string, flags zgrab2.BaseFlags) (net.Conn, error) {
	match := endpointRegex.FindStringSubmatch(endpointUrl)
	var address = ""
	if len(match) >= 3 && match[2] != "" {
		address = net.JoinHostPort(t.target.Host(), match[2])
	} else {
		address = net.JoinHostPort(t.target.Host(), fmt.Sprintf("%d", t.config.Port))
	}

	return zgrab2.DialTimeoutConnection("tcp", address, flags.Timeout, flags.BytesReadLimit)
}

func monitorChannel(ctx context.Context, c *uasc.SecureChannel) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg := c.Receive(ctx)
			if msg.Err != nil {
				return
			}
		}
	}
}
