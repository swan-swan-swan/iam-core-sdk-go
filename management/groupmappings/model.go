package groupmappings

// Mapping is one Role Open ID to OIDC Client group value association.
type Mapping struct {
	RoleOpenID string
	GroupValue string
}

// Snapshot is the complete authoritative mapping state for one OIDC Client.
type Snapshot struct {
	ApplicationOpenID string
	ClientID          string
	Mappings          []Mapping
	Revision          uint64
	Hash              string
}

// Conflict can be decoded from client.ErrorData for a stale mapping revision.
type Conflict struct {
	Revision uint64 `json:"revision"`
	Hash     string `json:"hash"`
	Impact   Impact `json:"impact"`
}

// Impact is the non-sensitive summary returned with a mapping conflict.
type Impact struct {
	Action           string `json:"action"`
	AffectedMappings int    `json:"affectedMappings"`
}

type mappingWire struct {
	RoleOpenID string `json:"roleOpenId"`
	GroupValue string `json:"groupValue"`
}

type snapshotWire struct {
	ApplicationOpenID string        `json:"applicationOpenId"`
	ClientID          string        `json:"clientId"`
	Mappings          []mappingWire `json:"mappings"`
	Revision          uint64        `json:"revision"`
	Hash              string        `json:"hash"`
}

func (wire snapshotWire) snapshot() Snapshot {
	mappings := make([]Mapping, len(wire.Mappings))
	for index := range wire.Mappings {
		mappings[index] = Mapping{RoleOpenID: wire.Mappings[index].RoleOpenID, GroupValue: wire.Mappings[index].GroupValue}
	}
	return Snapshot{
		ApplicationOpenID: wire.ApplicationOpenID, ClientID: wire.ClientID,
		Mappings: mappings, Revision: wire.Revision, Hash: wire.Hash,
	}
}
