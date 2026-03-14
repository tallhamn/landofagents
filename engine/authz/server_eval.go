package authz

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/marcusmom/land-of-agents/engine/netscope"
	"github.com/marcusmom/land-of-agents/engine/protector"
)

func evaluateRequest(eval *protector.CedarEvaluator, agent, host string) (protector.CedarDecision, string, error) {
	decision, err := eval.Evaluate(protector.CedarRequest{
		Principal: fmt.Sprintf(`Agent::"%s"`, protector.CedarEscapeID(agent)),
		Action:    `Action::"http:Request"`,
		Resource:  fmt.Sprintf(`Resource::"%s"`, protector.CedarEscapeID(host)),
	})
	if err != nil {
		return protector.CedarError, host, err
	}
	if decision == protector.CedarPermit {
		return decision, host, nil
	}

	service := netscope.EffectiveDomain(host)
	if service == "" || service == host {
		return decision, host, nil
	}
	decision, err = eval.Evaluate(protector.CedarRequest{
		Principal: fmt.Sprintf(`Agent::"%s"`, protector.CedarEscapeID(agent)),
		Action:    `Action::"http:Request"`,
		Resource:  fmt.Sprintf(`Resource::"%s"`, protector.CedarEscapeID(service)),
	})
	return decision, service, err
}

type denyResponse struct {
	LOADenial bool   `json:"loa_denial"`
	Agent     string `json:"agent"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
}

func writeDeny(w http.ResponseWriter, agent, domain, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(denyResponse{
		LOADenial: true,
		Agent:     agent,
		Action:    "http:Request",
		Resource:  domain,
		Decision:  "deny",
		Reason:    reason,
	})
}
