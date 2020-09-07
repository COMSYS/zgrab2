package opcua_test

import (
	"encoding/json"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	zgrab_opcua "github.com/zmap/zgrab2/modules/opcua"
	"github.com/zmap/zgrab2/modules/opcua/browser"
	opcua_test_infra "github.com/zmap/zgrab2/modules/opcua/test"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func NewServer(path string, opts ...opcua.Option) (*opcua_test_infra.Server, zgrab2.ScanTarget) {
	server := opcua_test_infra.NewServer(path, opts...)
	log.Infof("Running server on port %d and endpoint %s", server.Port, server.Endpoint)
	target := zgrab2.ScanTarget{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: &server.Port,
	}
	return server, target
}

func NewScanner() *zgrab_opcua.Scanner {
	scanner := new(zgrab_opcua.Scanner)
	scanner.Init(&zgrab_opcua.Flags{
		BaseFlags: zgrab2.BaseFlags{
			Timeout: 10 * time.Second,
		},
		BrowseTimeout: time.Second * 5,
		SleepTime:     time.Microsecond,
	})
	return scanner
}

func TestScanner_Scan(t *testing.T) {
	server, target := NewServer("test/rw_server.py", opcua.SecurityMode(ua.MessageSecurityModeNone))
	defer server.Close()

	// Scan the test target
	scanner := NewScanner()
	status, data, err := scanner.Scan(target)
	if err != nil {
		t.Fatalf("Error while scanning: %s", err.Error())
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("Scan status is %s", string(status))
	}

	ret, ok := data.(*zgrab_opcua.Log)
	if !ok {
		t.Fatal("Cannot read response from scanner")
	}

	// Check retrieved nodes
	nodes := make(map[string]browser.NodeDef)
	for _, n := range ret.EndpointNodes[ret.Endpoints[0].EndpointURL] {
		nodes[n.NodeID] = n
	}

	nodeClassVar := ua.NodeClassVariable
	nodeClassObject := ua.NodeClassObject

	nodeWritable := ua.AccessLevelTypeCurrentRead | ua.AccessLevelTypeCurrentWrite
	nodeReadable := ua.AccessLevelTypeCurrentRead

	parent := "ns=2;s=main"
	nodeRwInt := "rw_int32"
	nodeRoInt := "ro_int32"

	dataTypeInt := "i=6"
	dataTypeBool := "i=1"
	serverStatusFolder := "i=2253"

	nameNamespaceArray := "NamespaceArray"
	nameServerStatus := "ServerStatus"

	checkNodes := []browser.NodeDef{
		{
			NodeID:      "ns=2;s=rw_int32",
			NodeClass:   &nodeClassVar,
			AccessLevel: &nodeWritable,
			Parent:      &parent,
			BrowseName:  &nodeRwInt,
			DisplayName: &nodeRwInt,
			DataType:    &dataTypeInt,
		},
		{
			NodeID:      "ns=2;s=ro_int32",
			NodeClass:   &nodeClassVar,
			AccessLevel: &nodeReadable,
			Parent:      &parent,
			BrowseName:  &nodeRoInt,
			DisplayName: &nodeRoInt,
			DataType:    &dataTypeInt,
		},
		{
			NodeID:      "ns=2;s=rw_bool",
			NodeClass:   &nodeClassVar,
			AccessLevel: &nodeWritable,
			Parent:      &parent,
			DataType:    &dataTypeBool,
		},
		{
			NodeID:      "ns=2;s=rw_bool",
			NodeClass:   &nodeClassVar,
			AccessLevel: &nodeWritable,
			Parent:      &parent,
			DataType:    &dataTypeBool,
		},
		{
			NodeID:    "ns=2;s=main",
			NodeClass: &nodeClassObject,
		},
		{
			NodeID:          "i=2255",
			NodeClass:       &nodeClassVar,
			BrowseName:      &nameNamespaceArray,
			DisplayName:     &nameNamespaceArray,
			AccessLevel:     &nodeReadable,
			UserAccessLevel: &nodeReadable,
			Parent:          &serverStatusFolder,
		},
		{
			NodeID:          "i=2256",
			BrowseName:      &nameServerStatus,
			DisplayName:     &nameServerStatus,
			AccessLevel:     &nodeReadable,
			UserAccessLevel: &nodeReadable,
			Parent:          &serverStatusFolder,
		},
	}
	// Check if the above nodes have all specified properties
	for _, checkNode := range checkNodes {
		requireNode(checkNode, &nodes, t)
	}
	// Additional checks on node values
	if val, ok := (*nodes["ns=2;s=rw_int32"].Value).(int32); !ok || val != 5 {
		t.Fatalf("Node 'ns=2;s=rw_int32' should have a value of 5. Is: %d", val)
	}
	if val, ok := (*nodes["ns=2;s=ro_bool"].Value).(bool); !ok || !val {
		t.Fatalf("Node 'ns=2;s=ro_bool' should have a value of true. Is: %t", val)
	}
	if val, ok := (*nodes["i=2255"].Value).([]string); !ok || !contains(val, "http://opcfoundation.org/UA/") {
		t.Fatalf("Namespace array should contain the default namespace: Is: %v", val)
	}
	serverStatus, ok := (*nodes["i=2256"].Value).(*ua.ServerStatusDataType)
	if !ok {
		t.Fatalf("Server status node has no value")
	}
	if serverStatus.BuildInfo == nil || serverStatus.BuildInfo.ManufacturerName != "FreeOpcUa" {
		t.Fatalf("ManufacturerName in Serverstatus wrong. Expected: 'FreeOpcUA', Is: '%s'", serverStatus.BuildInfo.ManufacturerName)
	}

	// Check endpoint description
	if len(ret.Endpoints) == 0 {
		t.Fatal("List of endpoints should not be empty")
	}

	is := func(endpoint, name string, expected, actual interface{}) {
		if expected != actual {
			t.Fatalf("Endpoint %s hs rong value for %s. Expected: '%s' Actual: '%s'", endpoint, name, expected, actual)
		}
	}

	has := func(endpoint, name string, expected, empty interface{}) {
		if expected == empty {
			t.Fatalf("Endpoint %s is missing value for %s.", endpoint, name)
		}
	}

	for _, endpoint := range ret.Endpoints {
		has(endpoint.EndpointURL, "Server", endpoint.Server, nil)
		has(endpoint.EndpointURL, "SecurityPolicyURI", endpoint.SecurityPolicyURI, "")
		has(endpoint.EndpointURL, "TransportProfileURI", endpoint.TransportProfileURI, "")
		has(endpoint.EndpointURL, "ApplicationURI", endpoint.Server.ApplicationURI, "")
		has(endpoint.EndpointURL, "UserIdentityTokens", endpoint.UserIdentityTokens, nil)

		is(endpoint.EndpointURL, "ApplicationURI", endpoint.Server.ApplicationURI, "urn:freeopcua:python:server")
		is(endpoint.EndpointURL, "ProductURI", endpoint.Server.ProductURI, "urn:freeopcua.github.io:python:server")
		is(endpoint.EndpointURL, "ApplicationType", endpoint.Server.ApplicationType, ua.ApplicationTypeClientAndServer)
	}
}

func TestScanner_ScanSecure(t *testing.T) {
	server, target := NewServer("test/secure_server.py", opcua.SecurityMode(ua.MessageSecurityModeNone))
	defer server.Close()

	// Scan the test target
	scanner := NewScanner()
	status, data, err := scanner.Scan(target)
	if err != nil {
		t.Fatalf("Error while scanning: %s", err.Error())
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("Scan status is %s", string(status))
	}

	_, ok := data.(*zgrab_opcua.Log)
	if !ok {
		t.Fatal("Cannot read response from scanner")
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func requireNode(node browser.NodeDef, nodes *map[string]browser.NodeDef, t *testing.T) {
	log.Infof("Checking node %s", node.NodeID)
	scanned, ok := (*nodes)[node.NodeID]
	if !ok {
		t.Fatalf("Node with id '%s' not discovered by scanner", node.NodeID)
	}

	compare := func(name string, expected interface{}, actual interface{}) {
		if expected != nil && expected != actual {
			t.Fatalf("%s mismatches for node %s. Expected: '%s', is: '%s'", name, node.NodeID, expected, actual)
		}
	}

	fields := reflect.TypeOf(node)
	expectedValues := reflect.ValueOf(node)
	actualValues := reflect.ValueOf(scanned)

	for i := 0; i < fields.NumField(); i++ {
		field := fields.Field(i).Name
		expected := expectedValues.Field(i)
		actual := actualValues.Field(i)

		if expected.Kind() != actual.Kind() {
			t.Fatalf("Expected value for '%s' to be of kind '%s'", field, expected.Kind().String())
		}

		if expected.Kind() == reflect.Ptr {
			if expected.IsNil() {
				// We permit the actual value to be not nil, i.e., we just don't want to specify it exactly
				continue
			}
			if actual.IsNil() {
				t.Fatalf("%s mismatch. Expected: '%s', is: 'nil'", field, expected)
			}
			if !expected.IsNil() {
				expected = expected.Elem()
				actual = actual.Elem()
			}
		}

		switch expected.Kind() {
		case reflect.String:
			compare(field, expected.String(), actual.String())
		case reflect.Bool:
			compare(field, expected.Bool(), actual.Bool())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			compare(field, expected.Uint(), actual.Uint())
		default:
			t.Fatalf("Comparing field %s of type %s is not implemented", field, expected.Kind())
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(scanned)
}
