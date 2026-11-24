package kinds

// CodeMention records a GitHub file mentioning an in-scope root. It stores the match URL, never
// the matched text, and remains visible while its root is in scope.
var CodeMention = define[CodeMentionAttrs](Kind{
	Name: "code_mention", Singular: "code mention", Category: "code mentions",
	HostAttr: "root", Change: "code mention",
})

// CodeMentionAttrs describes the searched root, repository, file path and semicolon-separated
// matching hostnames. Hostnames is written even when empty so merged matches keep it paired
// with the same search's root. Non-current records lose these attributes; the URL key still
// identifies the repository and path.
type CodeMentionAttrs struct {
	Root       string `json:"root"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Hostnames  string `json:"hostnames"`
}
