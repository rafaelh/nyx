package cli

import "runtime/debug"

const develVersion = "devel"

// versionString reads the module's build version, including VCS pseudo-versions and +dirty. An
// absent version returns ""; Execute supplies develVersion.
func versionString(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}
