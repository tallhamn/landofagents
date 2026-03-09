package codifier

import (
	"fmt"

	"github.com/cedar-policy/cedar-go"
)

// ValidateCedar checks that the given text is syntactically valid Cedar.
func ValidateCedar(text string) error {
	_, err := cedar.NewPolicySetFromBytes("validate.cedar", []byte(text))
	if err != nil {
		return fmt.Errorf("invalid Cedar: %w", err)
	}
	return nil
}
