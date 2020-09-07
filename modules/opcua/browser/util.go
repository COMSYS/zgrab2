package browser

import "github.com/gopcua/opcua/ua"

var (
	nodeAttrs, nodeSpecificAttrs = buildAttributesLists()
)

func buildAttributesLists() ([]ua.AttributeID, map[ua.NodeClass][]ua.AttributeID) {
	// DataType attribute must be before value for decoding!
	// see OPC 10000-3: 5 Standard NodeClasses
	nodeBaseAttrs := []ua.AttributeID{
		ua.AttributeIDBrowseName,
		ua.AttributeIDDisplayName,
		ua.AttributeIDDescription,
		ua.AttributeIDWriteMask,
		ua.AttributeIDUserWriteMask,
		ua.AttributeIDRolePermissions,
		ua.AttributeIDUserRolePermissions,
	}

	nodeSpecificAttrs := make(map[ua.NodeClass][]ua.AttributeID)
	nodeSpecificAttrs[ua.NodeClassReferenceType] = []ua.AttributeID{
		ua.AttributeIDIsAbstract,
		ua.AttributeIDSymmetric,
		ua.AttributeIDInverseName,
	}
	nodeSpecificAttrs[ua.NodeClassView] = []ua.AttributeID{
		ua.AttributeIDContainsNoLoops,
		ua.AttributeIDEventNotifier,
	}
	nodeSpecificAttrs[ua.NodeClassObject] = []ua.AttributeID{
		ua.AttributeIDEventNotifier,
	}
	nodeSpecificAttrs[ua.NodeClassObjectType] = []ua.AttributeID{
		ua.AttributeIDIsAbstract,
	}
	nodeSpecificAttrs[ua.NodeClassVariable] = []ua.AttributeID{
		ua.AttributeIDDataType,
		ua.AttributeIDValueRank,
		ua.AttributeIDArrayDimensions,
		ua.AttributeIDValue,
		ua.AttributeIDIsAbstract,
		ua.AttributeIDAccessLevel,
		ua.AttributeIDUserAccessLevel,
		ua.AttributeIDHistorizing,
	}
	nodeSpecificAttrs[ua.NodeClassVariableType] = []ua.AttributeID{
		ua.AttributeIDAccessLevel,
		ua.AttributeIDDataType,
		ua.AttributeIDValue,
	}
	nodeSpecificAttrs[ua.NodeClassMethod] = []ua.AttributeID{
		ua.AttributeIDExecutable,
		ua.AttributeIDUserExecutable,
	}
	return nodeBaseAttrs, nodeSpecificAttrs
}
