package contain

import (
	"os"
	"path/filepath"
)

func copyKitConfig(src, dst string) error {
	for _, subdir := range []string{"config", "policies"} {
		srcDir := filepath.Join(src, subdir)
		dstDir := filepath.Join(dst, subdir)
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dstDir, e.Name()), data, 0644); err != nil {
				return err
			}
		}
	}
	os.MkdirAll(filepath.Join(dst, "audit"), 0755)
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
