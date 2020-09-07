package opcua

import (
	"github.com/gopcua/opcua/ua"
	"github.com/zmap/zgrab2/modules/opcua/browser"
	"time"
)

type Log struct {
	IsOpcUa                 bool                         `json:"is_opcua"`
	Endpoints               []*ua.EndpointDescription    `json:"endpoints,omitempty"`
	Servers                 []*ua.ApplicationDescription `json:"discovery_servers,omitempty"`
	SecurityPolicies        []string                     `json:"security_policies,omitempty"`
	EndpointNodes           map[string][]browser.NodeDef `json:"nodes,omitempty"`
	Panic                   bool                         `json:"is_opcua,omitempty"`
	ErrorMsg                string                       `json:"errormsg,omitempty"`
	RejectsSelfSigned       bool                         `json:"rejects_self_signed,omitempty"`
	Incomplete              bool                         `json:"incomplete,omitempty"`
	ScanDuration            time.Duration                `json:"scan_duration,omitempty"`
	EndpointSecUsed         map[string]EndpointSecurity  `json:"endpoint_sec_used,omitempty"`
	ScanStatus              string                       `json:"scan_status,omitempty"`
	AbortStage              string                       `json:"abort_stage,omitempty"`
	RDNS                    string                       `json:"rdns,omitempty"`
	ReadDuration            time.Duration                `json:"read_duration,omitempty"`
	BrowseDuration          time.Duration                `json:"browse_duration,omitempty"`
	NumReadReq              uint64                       `json:"num_read_req,omitempty"`
	NumBrowseReq            uint64                       `json:"num_browse_req,omitempty"`
	BytesRead               int                          `json:"bytes_read,omitempy"`
	BytesWritten            int                          `json:"bytes_written,omitempy"`
	EndpointCertificateTest map[string]*string           `json:"endpoint_cert_test,omitempy"`
}

type EndpointSecurity struct {
	SecurityMode      ua.MessageSecurityMode `json:"security_mode,omitempty"`
	SecurityLevel     uint8                  `json:"security_level,omitempty"`
	SecurityPolicyURI string                 `json:"security_policy_uri,omitempty"`
	RejectsSelfSigned bool                   `json:"rejects_self_signed,omitempty"`
	CertificateError  string                 `json:"certificate_error,omitempty"`
}
