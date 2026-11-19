package kinds

// CodeMention is a public repository file that mentions an in-scope root
// domain, found by the github stage's code search. It is a location only: the
// matched text is never stored. It is keyed by the match's URL on GitHub and is
// shown while its root is in scope.
var CodeMention = define[CodeMentionAttrs](Kind{
	Name: "code_mention", Singular: "code mention", Category: "code mentions",
	HostAttr: "root", Change: "code mention",
})

// CodeMentionAttrs: the root that was searched for, the repository ("owner/name"),
// the file's path in it and the hostnames under an in-scope root that the match's
// fragment named (";"-joined). Hostnames is always written, even empty, so that a
// file two roots' searches both match keeps the hostnames of the same search as
// its root, not a mix of the two. The match's URL is the key. A record that is no
// longer current keeps none of these: the store holds attributes only from current
// observations, and the key names the repository and the path.
type CodeMentionAttrs struct {
	Root       string `json:"root"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Hostnames  string `json:"hostnames"`
}
