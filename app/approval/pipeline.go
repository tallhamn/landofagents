// Package approval implements the interactive approval flow: watching for
// denials, running them through the Advocate -> Codifier pipeline, prompting
// the user, and writing approved policies.
package approval

// PipelineConfig configures the approval pipeline.
type PipelineConfig struct {
	KitDir string
	APIKey string // empty = fallback to DescriptionFromDenial + template Cedar
}

// ProposalWithCedar is the output of the pipeline: English description + compiled Cedar.
type ProposalWithCedar struct {
	Description string
	Reasoning   string
	Agent       string
	DenialIDs   []string
	Cedar       string // compiled Cedar policy text
	Filename    string // e.g. "goggins-http-wrike.cedar"
}

// PipelineResult holds all proposals generated from a batch of denials.
type PipelineResult struct {
	Proposals []ProposalWithCedar
}

// Pipeline runs denials through Advocate -> Codifier to produce Cedar policies.
type Pipeline struct {
	cfg PipelineConfig
}

// NewPipeline creates a new approval pipeline.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	return &Pipeline{cfg: cfg}
}
