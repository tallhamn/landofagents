package config

import "encoding/json"

// CedarEntity represents a single entity in Cedar JSON format.
type CedarEntity struct {
	UID     CedarUID       `json:"uid"`
	Attrs   map[string]any `json:"attrs"`
	Parents []CedarUID     `json:"parents"`
}

// CedarUID is the type+id pair used in Cedar entity format.
type CedarUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EntitiesToCedarJSON converts the agent registry data to Cedar JSON entity format.
func (e *Entities) EntitiesToCedarJSON() ([]byte, error) {
	var entities []CedarEntity

	// Create agent entities — each agent is a member of agent groups
	for name := range e.Agents {
		parents := []CedarUID{}
		// Check which groups this agent belongs to
		for groupName, group := range e.AgentGroups {
			for _, member := range group.Members {
				if member == name {
					parents = append(parents, CedarUID{Type: "AgentGroup", ID: groupName})
				}
			}
		}
		entities = append(entities, CedarEntity{
			UID:     CedarUID{Type: "Agent", ID: name},
			Attrs:   map[string]any{},
			Parents: parents,
		})
	}

	// Create agent group entities
	for groupName := range e.AgentGroups {
		entities = append(entities, CedarEntity{
			UID:     CedarUID{Type: "AgentGroup", ID: groupName},
			Attrs:   map[string]any{},
			Parents: []CedarUID{},
		})
	}

	// Create recipient entities
	for groupName, group := range e.RecipientGroups {
		// Create the group entity
		entities = append(entities, CedarEntity{
			UID:     CedarUID{Type: "RecipientGroup", ID: groupName},
			Attrs:   map[string]any{},
			Parents: []CedarUID{},
		})
		// Create each member as a Recipient with parent group
		for _, member := range group.Members {
			entities = append(entities, CedarEntity{
				UID:     CedarUID{Type: "Recipient", ID: member},
				Attrs:   map[string]any{},
				Parents: []CedarUID{{Type: "RecipientGroup", ID: groupName}},
			})
		}
	}

	return json.MarshalIndent(entities, "", "  ")
}
