package authz

import (
	"fmt"
	"testing"

	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/protector"
)

// BenchmarkPolicyReloadPath measures the current per-request reload path:
// LoadKit + EntitiesToCedarJSON + Cedar evaluator construction + one evaluate call.
func BenchmarkPolicyReloadPath(b *testing.B) {
	kitDir := testdataDir()
	req := protector.CedarRequest{
		Principal: fmt.Sprintf(`Agent::%q`, "goggins"),
		Action:    `Action::"http:Request"`,
		Resource:  `Resource::"api.wrike.com"`,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kit, err := config.LoadKit(kitDir)
		if err != nil {
			b.Fatalf("LoadKit: %v", err)
		}
		entitiesJSON, err := kit.Entities.EntitiesToCedarJSON()
		if err != nil {
			b.Fatalf("EntitiesToCedarJSON: %v", err)
		}

		eval, err := protector.NewCedarEvaluatorFromSources(
			[]byte(kit.AlwaysAllowedCedar),
			kit.Policies,
			entitiesJSON,
		)
		if err != nil {
			b.Fatalf("NewCedarEvaluatorFromSources: %v", err)
		}
		_, err = eval.Evaluate(req)
		eval.Cleanup()
		if err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
	}
}
