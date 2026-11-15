package kinds

// Script is a script file a crawled page references with <script src>, whatever
// host it is on. The crawl records one for every such element it sees; the
// jsparse stage fetches only those on in-scope hosts. A record is shown while its
// host is in scope, and the egress policy lets jsparse request only these URLs.
var Script = define[ScriptAttrs](Kind{Name: "script", HostAttr: "host"})

// ScriptAttrs: URL is the normalised script URL (the record's key), Host its
// host, and Service the origin of the web service whose crawl saw it.
type ScriptAttrs struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Service string `json:"service"`
}

// ScriptParsed marks a script the jsparse stage has completed a check for, keyed
// by the script's URL. It lets a script that was fetched keep its place within the
// per-origin cap when new scripts sort before it.
var ScriptParsed = defineBare(Kind{Name: "script_parsed"})
