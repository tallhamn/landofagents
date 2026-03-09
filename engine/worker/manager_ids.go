package worker

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func newWorkerID() string {
	buf := make([]byte, 6)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("wk_%d", time.Now().UnixNano())
	}
	return "wk_" + hex.EncodeToString(buf)
}

func configuredMaxDepth() (int, error) {
	raw := strings.TrimSpace(os.Getenv("LOA_WORKER_MAX_DEPTH"))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid LOA_WORKER_MAX_DEPTH %q (must be integer >= 0)", raw)
	}
	return n, nil
}
