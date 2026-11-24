package kinds

// Script records a crawled page's <script src> URL, including references outside scope. Only
// in-scope scripts are shown and fetched by jsparse; egress restricts jsparse to these recorded
// URLs.
var Script = define[ScriptAttrs](Kind{Name: "script", HostAttr: "host"})

// ScriptAttrs identifies the normalised script URL, its host and the web-service origin that
// referenced it.
type ScriptAttrs struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Service string `json:"service"`
}

// ScriptParsed marks completed jsparse URLs so fetched scripts retain their per-origin cap
// slots when new URLs sort ahead of them.
var ScriptParsed = defineBare(Kind{Name: "script_parsed"})
