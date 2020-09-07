package browser

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	log "github.com/sirupsen/logrus"
	"math"
	"strings"
	"time"
)

type UABrowse struct {
	Client            *opcua.Client
	Nodes             map[string]*NodeDef
	Host              string
	SleepTime         time.Duration
	BrowseChunkSize   int
	ReadChunkSize     int
	NumReadReq        uint64
	NumBrowseReq      uint64
	ReadReqDuration   time.Duration
	BrowseReqDuration time.Duration
	MaxChildren       int
	InitialNodeIds    string
	log               *log.Entry
}

type NodeDef struct {
	NodeID              string                    `json:"node_id"`
	NodeClass           *ua.NodeClass             `json:"node_class,omitempty"`
	BrowseName          *string                   `json:"browse_name,omitempty"`
	Description         *string                   `json:"description,omitempty"`
	AccessLevel         *ua.AccessLevelType       `json:"access_level,omitempty"`
	UserAccessLevel     *ua.AccessLevelType       `json:"user_access_level,omitempty"`
	DataType            *string                   `json:"data_type,omitempty"`
	Writable            *bool                     `json:"writable,omitempty"`
	Value               *interface{}              `json:"value,omitempty"`
	DisplayName         *string                   `json:"display_name,omitempty"`
	ValueStatus         *string                   `json:"value_status,omitempty"`
	WriteMask           *uint32                   `json:"write_mask,omitempty"`
	UserWriteMask       *uint32                   `json:"user_write_mask,omitempty"`
	RolePermissions     *[]*ua.RolePermissionType `json:"role_permissions,omitempty"`
	UserRolePermissions *[]*ua.RolePermissionType `json:"user_role_permissions,omitempty"`
	IsAbstract          *bool                     `json:"is_abstract,omitempty"`
	Symmetric           *bool                     `json:"symmetric,omitempty"`
	InverseName         *string                   `json:"inverse_name,omitempty"`
	ContainsNoLoops     *bool                     `json:"contains_no_loops,omitempty"`
	EventNotifier       *string                   `json:"event_notifier,omitempty"`
	ValueRank           *int64                    `json:"value_rank,omitempty"`
	ArrayDimensions     *[]uint32                 `json:"array_dimensions,omitempty"`
	Executable          *bool                     `json:"executable,omitempty"`
	UserExecutable      *bool                     `json:"user_executable,omitempty"`
	ValueRaw            *string                   `json:"value_raw,omitempty"`
	Parent              *string                   `json:"parent,omitempty"`
	RelationType        *string                   `json:"relation_type,omitempty"`
	ReadTime            *time.Time                `json:"read_time,omitempty"`
	ServerTime          *time.Time                `json:"server_time,omitempty"`
	ResponseTime        *time.Time                `json:"response_time,omitempty"`
	Historizing         *bool                     `json:"historizing,omitempty"`
}

type browseRef struct {
	node            *ua.NodeID
	includeSubtypes bool
}

func (t *UABrowse) BrowseBFS(ctx context.Context) error {
	t.log = contextLogger(ctx)
	var browseQueue, readQueue []*ua.NodeID

	// Initialize browse queue with nodes to start search on
	initialIDs, err := parseNodeIDlist(t.InitialNodeIds)
	if err != nil {
		panic(err)
	}
	browseQueue = append(browseQueue, initialIDs...)

	refTypes := []browseRef{
		{ua.NewNumericNodeID(0, id.HasChild), true},
		{ua.NewNumericNodeID(0, id.Organizes), false},
		{ua.NewNumericNodeID(0, id.HasEventSource), true},
	}

	retryCounter := 3
	for len(browseQueue) > 0 {
		// do not overload server with too many requests
		time.Sleep(t.SleepTime)
		end := t.BrowseChunkSize
		if end > len(browseQueue) {
			end = len(browseQueue)
		}
		chunk := browseQueue[:end]
		browseQueue = browseQueue[end:]
		t.log.Debugf("Querying %d nodes for references. Queuelen: %d", len(chunk), len(browseQueue))

		nodesToBrowse := nodesToBrowseFor(chunk, refTypes)

		// Issue browse request
		tRequest := time.Now()
		browseResult, err := t.Client.Browse(&ua.BrowseRequest{
			View: &ua.ViewDescription{
				ViewID:    ua.NewTwoByteNodeID(0),
				Timestamp: time.Now(),
			},
			RequestedMaxReferencesPerNode: 100,
			NodesToBrowse:                 nodesToBrowse,
		})
		t.BrowseReqDuration += time.Since(tRequest)
		t.NumBrowseReq += 1
		if err != nil {
			if code, ok := err.(ua.StatusCode); ok {
				switch code {
				case ua.StatusBadEncodingLimitsExceeded,
					ua.StatusBadRequestTooLarge,
					ua.StatusBadResponseTooLarge,
					ua.StatusBadTimeout,
					ua.StatusBadTooManyOperations:
					if t.BrowseChunkSize > 5 {
						browseQueue = append(browseQueue, chunk...)
						t.BrowseChunkSize = t.BrowseChunkSize / 2
						t.log.Debugf("Browse returned error: %s. Reduced browse chunk size to %d", code.Error(), t.BrowseChunkSize)
						continue
					}
				case ua.StatusBadUnexpectedError:
					// try skipping this chunk
					retryCounter -= 1
					if retryCounter > 0 {
						t.log.Debugf("Browse returned error: %s. Retrying...", code.Error())
						continue
					}
				}
			}
			t.log.Errorf("Error while browsing nodes: %s", err.Error())
			return err
		}
		if t.BrowseChunkSize < 100 {
			t.BrowseChunkSize += 1
		}
		retryCounter = 3

		for i, result := range browseResult.Results {
			extractedNodes, _ := t.extractBrowseResults(result, nodesToBrowse[i])
			if len(extractedNodes) > t.MaxChildren {
				extractedNodes = extractedNodes[:t.MaxChildren]
			}
			browseQueue = append(browseQueue, extractedNodes...)
			readQueue = append(readQueue, extractedNodes...)
		}

		t.log.Debugf("Got browse response. browse queue: %d, read queue: %d, total seen: %d, browse chunk size: %d, read chunk size: %d",
			len(browseQueue), len(readQueue), len(t.Nodes), t.BrowseChunkSize, t.ReadChunkSize)

		// read attributes for known nodes before continuing with next chunk / level
		if len(readQueue) > 25 || len(browseQueue) == 0 && len(readQueue) > 0 {
			err = t.readNodeAttributes(readQueue)
			if err != nil {
				// this might happen on custom object types.
				if !strings.HasPrefix(err.Error(), "opcua: invalid extension object with id") {
					t.log.Errorf("Error while reading nodes after browse: %s", err.Error())
					return err
				}
			}
			// reset readQueue
			readQueue = readQueue[0:0]
		}
	}
	t.log.Debug("Browse completed")
	return nil
}

func parseNodeIDlist(list string) ([]*ua.NodeID, error) {
	var result []*ua.NodeID
	for _, s := range strings.Split(list, ",") {
		nodeID, err := ua.ParseNodeID(s)
		if err != nil {
			log.Errorf("Could not parse initial node id '%s'", s)
			return nil, err
		}
		result = append(result, nodeID)
	}
	return result, nil
}

func nodesToBrowseFor(chunkNodes []*ua.NodeID, refTypes []browseRef) []*ua.BrowseDescription {
	var browseDescs []*ua.BrowseDescription
	for _, nodeID := range chunkNodes {
		for _, ref := range refTypes {
			browseDescs = append(browseDescs, &ua.BrowseDescription{
				NodeID:          nodeID,
				BrowseDirection: ua.BrowseDirectionForward,
				ReferenceTypeID: ref.node,
				IncludeSubtypes: ref.includeSubtypes,
				ResultMask:      uint32(ua.BrowseResultMaskAll),
			})
		}
	}
	return browseDescs
}

func (t *UABrowse) extractBrowseResults(result *ua.BrowseResult, desc *ua.BrowseDescription) ([]*ua.NodeID, error) {
	var extractedNodes []*ua.NodeID
	parent := desc.NodeID.String()
	refTypeName := desc.ReferenceTypeID.String()
	queue := []*ua.BrowseResult{result}

	for len(queue) > 0 {
		result = queue[0]
		queue = queue[1:]
		if result.StatusCode == ua.StatusOK {
			for _, ref := range result.References {
				nodeID := ref.NodeID.NodeID

				// Deduplicate by skipping already known nodes
				if _, ok := t.Nodes[nodeID.String()]; ok {
					continue
				}
				def := addNodeFromReference(nodeID, ref, parent, refTypeName)
				t.Nodes[nodeID.String()] = def
				extractedNodes = append(extractedNodes, nodeID)
			}
		}
		if result.ContinuationPoint == nil {
			return extractedNodes, nil
		}

		if len(extractedNodes) > t.MaxChildren {
			// free continuation point on server
			_, err := t.Client.BrowseNext(&ua.BrowseNextRequest{
				ReleaseContinuationPoints: true,
				ContinuationPoints:        [][]byte{result.ContinuationPoint},
			})
			if err != nil {
				t.log.Debugf("Error while releasing continuation point : '%s'", err.Error())
			}
			return extractedNodes, nil
		}

		// Sleep, then continue browsing at given ContinuationPoint
		browseNextResult, err := t.sendBrowseNextRequest(result)
		if err != nil {
			return extractedNodes, err
		}
		queue = append(queue, browseNextResult.Results...)
	}
	return extractedNodes, nil
}

func addNodeFromReference(nodeID *ua.NodeID, ref *ua.ReferenceDescription, parent string, refTypeName string) *NodeDef {
	def := &NodeDef{
		NodeID: nodeID.String(),
	}
	if ref.NodeClass != ua.NodeClassUnspecified {
		def.NodeClass = &ref.NodeClass
	}
	if ref.BrowseName.Name != "" {
		def.BrowseName = &ref.BrowseName.Name
	}
	if ref.DisplayName.Text != "" {
		def.DisplayName = &ref.DisplayName.Text
	}
	if ref.ReferenceTypeID != nil && ref.ReferenceTypeID.String() != "" {
		refTypeName = ref.ReferenceTypeID.String()
	}
	if ref.TypeDefinition != nil {
		dataType := ref.TypeDefinition.NodeID.String()
		def.DataType = &dataType
	}
	def.Parent = &parent
	def.RelationType = &refTypeName
	return def
}

func (t *UABrowse) sendBrowseNextRequest(result *ua.BrowseResult) (*ua.BrowseNextResponse, error) {
	time.Sleep(t.SleepTime)
	tRequest := time.Now()
	res, err := t.Client.BrowseNext(&ua.BrowseNextRequest{
		ReleaseContinuationPoints: false,
		ContinuationPoints:        [][]byte{result.ContinuationPoint},
	})
	t.BrowseReqDuration += time.Since(tRequest)
	t.NumBrowseReq += 1
	if err != nil {
		t.log.Errorf("Error while browsing next nodes: %s", err.Error())
		return res, err
	}
	return res, nil
}

func (t *UABrowse) readNodeAttributes(nodes []*ua.NodeID) error {
	var nodesToRead []*ua.ReadValueID
	for _, node := range nodes {
		nodeDef, exists := t.Nodes[node.String()]
		if exists && (nodeDef.NodeClass == nil || *nodeDef.NodeClass == ua.NodeClassUnspecified) {
			nodesToRead = append(nodesToRead, &ua.ReadValueID{
				NodeID:      node,
				AttributeID: ua.AttributeIDNodeClass,
			})
		}
	}
	err := t.readValuesChunked(nodesToRead)
	if err != nil {
		return err
	}

	nodesToRead = make([]*ua.ReadValueID, 0)
	for _, node := range nodes {
		nodeDef, exists := t.Nodes[node.String()]
		// skip nodes that do not exist
		if !exists || nodeDef.NodeClass == nil {
			continue
		}
		queryAttrs := nodeAttrs
		specificAttrs, exists := nodeSpecificAttrs[*nodeDef.NodeClass]
		if exists {
			queryAttrs = append(queryAttrs, specificAttrs...)
		}

		for _, attrID := range queryAttrs {
			// Skip attributes that are already known from browsing
			if attrID == ua.AttributeIDDisplayName && nodeDef.DisplayName != nil ||
				attrID == ua.AttributeIDBrowseName && nodeDef.BrowseName != nil ||
				attrID == ua.AttributeIDDataType && nodeDef.DataType != nil {
				continue
			}
			nodesToRead = append(nodesToRead, &ua.ReadValueID{
				NodeID:      node,
				AttributeID: attrID,
			})
		}
	}
	return t.readValuesChunked(nodesToRead)
}

func (t *UABrowse) readValuesChunked(nodesToRead []*ua.ReadValueID) error {
	retryCounter := 3
	for i := 0; i >= 0 && i < len(nodesToRead); i += t.ReadChunkSize {
		// do not overload server with too many requests
		time.Sleep(t.SleepTime)
		j := i + t.ReadChunkSize
		if j > len(nodesToRead) {
			j = len(nodesToRead)
		}
		tRequest := time.Now().UTC()
		readReq := &ua.ReadRequest{
			TimestampsToReturn: ua.TimestampsToReturnServer,
			NodesToRead:        nodesToRead[i:j],
		}
		t.NumReadReq += 1
		res, err := t.Client.Read(readReq)
		t.ReadReqDuration += time.Since(tRequest)
		tResponse := time.Now().UTC()
		if err != nil {
			if code, ok := err.(ua.StatusCode); ok {
				switch code {
				case ua.StatusBadEncodingLimitsExceeded,
					ua.StatusBadRequestTooLarge,
					ua.StatusBadResponseTooLarge,
					ua.StatusBadTimeout,
					ua.StatusBadTooManyOperations:
					if t.ReadChunkSize > 5 {
						// repeat first half of current request if chunk > 10
						// skip current chunk if already small chunk size (might be single element?)
						if t.ReadChunkSize > 10 {
							i -= t.ReadChunkSize
						}
						t.ReadChunkSize = t.ReadChunkSize / 2
						t.log.Debugf("Read request failed with '%s'. Reduced read chunksize to %d", code.Error(), t.ReadChunkSize)
					}
					continue
				case ua.StatusBadUnexpectedError:
					// try skipping this chunk
					retryCounter -= 1
					if retryCounter > 0 {
						t.log.Debugf("Read request failed with '%s'. Retrying...", code.Error())
						continue
					}
				}
			}
			return err
		}

		if t.ReadChunkSize < 200 {
			t.ReadChunkSize += 1
		}
		retryCounter = 3

		// parse results
		t.log.Debugf("Successfully read %d nodes", len(res.Results))
		for k, result := range res.Results {
			nodeID := nodesToRead[i+k].NodeID
			def, ok := t.Nodes[nodeID.String()]
			if !ok {
				// Initial nodes are not yet added during browse
				def = &NodeDef{
					NodeID: nodeID.String(),
				}
				t.Nodes[nodeID.String()] = def
			}
			t.processReadResults(result, nodesToRead[i+k].AttributeID, def, &tRequest, &tResponse)
		}
	}
	return nil
}

func StatusCodeString(n ua.StatusCode) string {
	if d, ok := ua.StatusCodes[n]; ok {
		return fmt.Sprintf("%s", d.Name)
	}
	return fmt.Sprintf("0x%X", uint32(n))
}

func (t *UABrowse) processReadResults(result *ua.DataValue, attr ua.AttributeID, def *NodeDef, tRead *time.Time, tResponse *time.Time) {
	if result.Status != ua.StatusOK {
		if attr == ua.AttributeIDValue {
			res := StatusCodeString(result.Status)
			def.ValueStatus = &res
		}
		return
	}
	if result.Value == nil {
		return
	}
	if def.ReadTime == nil {
		def.ReadTime = tRead
	}
	if def.ResponseTime == nil {
		def.ResponseTime = tResponse
	}
	if attr == ua.AttributeIDValue {
		// Update timestamp of the read request that contained the actual value
		// Keep any other timestamp in case node has no value
		def.ReadTime = tRead
		def.ServerTime = &result.ServerTimestamp
		def.ResponseTime = tResponse
	}
	t.extractDataValue(result, attr, def)
	return
}

func (t *UABrowse) extractDataValue(result *ua.DataValue, attr ua.AttributeID, def *NodeDef) {
	switch attr {
	case ua.AttributeIDNodeClass:
		res := ua.NodeClass(result.Value.Int())
		def.NodeClass = &res
	case ua.AttributeIDBrowseName:
		res := result.Value.String()
		def.BrowseName = &res
	case ua.AttributeIDDisplayName:
		res := result.Value.String()
		def.DisplayName = &res
	case ua.AttributeIDDescription:
		res := result.Value.String()
		def.Description = &res
	case ua.AttributeIDWriteMask:
		switch result.Value.Value().(type) {
		case uint32:
			res := result.Value.Value().(uint32)
			def.WriteMask = &res
		case int32:
			res := uint32(result.Value.Value().(int32))
			def.WriteMask = &res
		}
	case ua.AttributeIDUserWriteMask:
		switch result.Value.Value().(type) {
		case uint32:
			res := result.Value.Value().(uint32)
			def.WriteMask = &res
		case int32:
			res := uint32(result.Value.Value().(int32))
			def.WriteMask = &res
		}
	case ua.AttributeIDRolePermissions:
		numValues := len(result.Value.Value().([]*ua.ExtensionObject))
		results := make([]*ua.RolePermissionType, numValues)
		for i, value := range result.Value.Value().([]*ua.ExtensionObject) {
			results[i] = value.Value.(*ua.RolePermissionType)
		}
		def.RolePermissions = &results
	case ua.AttributeIDUserRolePermissions:
		numValues := len(result.Value.Value().([]*ua.ExtensionObject))
		results := make([]*ua.RolePermissionType, numValues)
		for i, value := range result.Value.Value().([]*ua.ExtensionObject) {
			results[i] = value.Value.(*ua.RolePermissionType)
		}
		def.UserRolePermissions = &results
	case ua.AttributeIDIsAbstract:
		res := result.Value.Bool()
		def.IsAbstract = &res
	case ua.AttributeIDSymmetric:
		res := result.Value.Bool()
		def.Symmetric = &res
	case ua.AttributeIDInverseName:
		res := result.Value.LocalizedText().Text
		def.InverseName = &res
	case ua.AttributeIDContainsNoLoops:
		res := result.Value.Bool()
		def.ContainsNoLoops = &res
	case ua.AttributeIDEventNotifier:
		res := ua.EventNotifierType(result.Value.Value().(uint8)).String()
		def.EventNotifier = &res
	case ua.AttributeIDValueRank:
		res := int64(result.Value.Value().(int32))
		def.ValueRank = &res
	case ua.AttributeIDArrayDimensions:
		res := result.Value.Value().([]uint32)
		def.ArrayDimensions = &res
	case ua.AttributeIDAccessLevel:
		res := ua.AccessLevelType(result.Value.Value().(uint8))
		def.AccessLevel = &res
	case ua.AttributeIDUserAccessLevel:
		res := ua.AccessLevelType(result.Value.Value().(uint8))
		def.UserAccessLevel = &res
	case ua.AttributeIDHistorizing:
		res := result.Value.Bool()
		def.Historizing = &res
	case ua.AttributeIDExecutable:
		res := result.Value.Bool()
		def.Executable = &res
	case ua.AttributeIDUserExecutable:
		res := result.Value.Bool()
		def.UserExecutable = &res
	case ua.AttributeIDDataType:
		res := result.Value.NodeID().String()
		def.DataType = &res
	case ua.AttributeIDValue:
		binary, err := result.Encode()
		if err != nil {
			t.log.Infof("Cannot encode value: %s", err.Error())
		} else {
			rawValue := base64.StdEncoding.EncodeToString(binary)
			def.ValueRaw = &rawValue
		}
		val := result.Value
		switch val.Value().(type) {
		case *ua.ExtensionObject:
			if extObj := val.ExtensionObject(); extObj != nil {
				def.Value = &extObj.Value
			}
		case []*ua.ExtensionObject:
			results := make([]*interface{}, 0)
			for _, value := range val.Value().([]*ua.ExtensionObject) {
				if extObj := value.Value; extObj != nil {
					results = append(results, &extObj)
				}
			}
			if len(results) > 0 {
				def.Value = results[0]
			}
		default:
			res := val.Value()
			switch res.(type) {
			case float64:
				if math.IsNaN(res.(float64)) {
					res = "NaN"
				} else if math.IsInf(res.(float64), 1) {
					res = "Inf"
				} else if math.IsInf(res.(float64), -1) {
					res = "-Inf"
				}
			case float32:
				f64 := float64(res.(float32))
				if math.IsNaN(f64) {
					res = "NaN"
				} else if math.IsInf(f64, 1) {
					res = "Inf"
				} else if math.IsInf(f64, -1) {
					res = "-Inf"
				}
			}
			def.Value = &res
		}
	default:
		t.log.Printf("Reading %s currently not implemented!", ua.AttributeID(attr).String())
	}
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
