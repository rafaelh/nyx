// Package output renders the engagement's TXT and CSV files from the store.
// Files are written to .nyx/tmp and renamed into place, so a reader never
// sees a truncated file.
package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/fault"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Format is TXT (plain list, current records only) or CSV (all records).
type Format int

const (
	TXT Format = iota
	CSV
)

// Row is one output row. Cells are the key and attribute columns.
type Row struct {
	Cells               []string
	Current             bool
	FirstSeen, LastSeen string
}

// Snapshot is the store contents a render works from.
type Snapshot struct {
	Today   string
	Inputs  []store.Input
	Records map[string][]store.Record // by kind, including not-current records
	Scope   *scope.Scope
	Inv     *inventory.Inventory
	// ASNNetblocks maps an in-scope netblock to the "AS<n>" input it came from.
	ASNNetblocks map[string]string
	// Vis decides which records are shown, for Scope and Inv; Render makes one
	// if it is nil. A caller that counts the same records passes its own, so
	// the files and the totals agree and each host is decided once.
	Vis *kinds.Visibility
	// Storage is the storage Attribution derived with the findings, which the
	// findings files are written from.
	Storage map[string]findings.StorageAttr
	// Changes are what changed since the run started (see changes.csv).
	Changes []Change
}

// File is a registry entry. CSV files get the columns Columns followed by
// current, first_seen and last_seen.
type File struct {
	Name    string
	Format  Format
	Columns []string
	Rows    func(Snapshot) []Row
	// Order, if set, sorts the rows instead of their cells.
	Order func(a, b Row) int
}

// Render writes every file via .nyx/tmp and renames it into dir. With fsync, each file reaches the
// disk before it is renamed, so a power loss cannot leave a renamed but empty file. On macOS that
// costs a full flush of the drive's cache per file, so tests turn it off.
func Render(dir string, files []File, snap Snapshot, fsync bool) error {
	return NewWriter(dir, fsync).Render(files, snap)
}

// Writer renders the files of one engagement again and again (a run renders after every pass),
// and rewrites only the files whose contents changed since it last wrote them. What it last wrote
// is kept in memory rather than compared with the files on disk, so the first render of every
// process writes every file.
type Writer struct {
	dir   string
	fsync bool
	wrote map[string][sha256.Size]byte // file name -> hash of the contents last written
}

// NewWriter returns a Writer for the engagement directory dir (see Render for fsync).
func NewWriter(dir string, fsync bool) *Writer {
	return &Writer{dir: dir, fsync: fsync, wrote: map[string][sha256.Size]byte{}}
}

// Render writes every file whose contents changed (see Writer).
func (w *Writer) Render(files []File, snap Snapshot) error {
	snap.Vis = snap.vis()
	tmp := filepath.Join(w.dir, ".nyx", "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		if err := w.renderFile(tmp, f, snap); err != nil {
			return fmt.Errorf("render %s: %w", f.Name, err)
		}
	}
	return nil
}

// Sweep removes stale temporary files left by an interrupted render.
func Sweep(dir string) error {
	tmp := filepath.Join(dir, ".nyx", "tmp")
	entries, err := os.ReadDir(tmp)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(tmp, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// renderFile writes f, or removes it when it would have no rows (a TXT file
// lists only current rows), so an empty file is never left in the engagement.
// This is deliberate: a file with only a header row tells the operator nothing,
// so a file's presence is itself the signal that there is something to read.
func (w *Writer) renderFile(tmp string, f File, snap Snapshot) error {
	rows := f.Rows(snap)
	if f.Format == TXT {
		rows = listedRows(rows)
	}
	if len(rows) == 0 {
		delete(w.wrote, f.Name)
		if err := os.Remove(filepath.Join(w.dir, f.Name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	order := f.Order
	if order == nil {
		order = func(a, b Row) int { return slices.Compare(a.Cells, b.Cells) }
	}
	slices.SortStableFunc(rows, order)
	var buf bytes.Buffer
	switch f.Format {
	case TXT:
		for _, r := range rows {
			buf.WriteString(sanitize.Text(r.Cells[0]))
			buf.WriteByte('\n')
		}
	case CSV:
		if err := writeCSV(&buf, f.Columns, rows); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	if last, ok := w.wrote[f.Name]; ok && last == sum {
		// Unchanged since this Writer wrote it, unless someone has removed it since.
		if _, err := os.Lstat(filepath.Join(w.dir, f.Name)); err == nil {
			return nil
		}
	}
	delete(w.wrote, f.Name) // a failed write leaves the file as it was, which may not be sum
	if err := writeAtomic(w.dir, tmp, f.Name, buf.Bytes(), w.fsync); err != nil {
		return err
	}
	w.wrote[f.Name] = sum
	return nil
}

// listedRows are the rows a TXT file lists: the current ones with a value.
func listedRows(rows []Row) []Row {
	var listed []Row
	for _, r := range rows {
		if r.Current && len(r.Cells) > 0 {
			listed = append(listed, r)
		}
	}
	return listed
}

// writeCSV writes a header of columns followed by current, first_seen and last_seen, then one
// record per row with its cells made safe for a spreadsheet.
func writeCSV(buf *bytes.Buffer, columns []string, rows []Row) error {
	w := csv.NewWriter(buf)
	if err := w.Write(append(append([]string(nil), columns...), "current", "first_seen", "last_seen")); err != nil {
		return err
	}
	for _, r := range rows {
		rec := make([]string, 0, len(r.Cells)+3)
		for _, c := range r.Cells {
			rec = append(rec, csvSafe(c))
		}
		rec = append(rec, fmt.Sprint(r.Current), r.FirstSeen, r.LastSeen)
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// writeAtomic writes data to name in tmp, syncing it when fsync is set, then renames it to name
// in dir, so a reader never sees a part-written file.
func writeAtomic(dir, tmp, name string, data []byte, fsync bool) error {
	tmpPath := filepath.Join(tmp, name)
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	half := len(data) / 2
	if _, err := out.Write(data[:half]); err != nil {
		out.Close()
		return err
	}
	fault.Point("render-mid-file")
	if _, err := out.Write(data[half:]); err != nil {
		out.Close()
		return err
	}
	if fsync {
		if err := out.Sync(); err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, name))
}

// csvSafe sanitises s, then neutralises spreadsheet formulas. Sanitising
// first means a leading control character cannot hide a formula prefix.
func csvSafe(s string) string {
	s = sanitize.Text(s)
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		s = "'" + s
	}
	return s
}

// Default returns the registered files: scope, candidates and excluded, then
// the DNS files, the web files, open-ports.csv, email-posture.csv, the
// findings files and changes.csv.
func Default() []File {
	files := []File{
		{Name: "scope.csv", Format: CSV, Columns: []string{"type", "value", "source"}, Rows: scopeRows},
		{Name: "candidates.csv", Format: CSV, Columns: candidateColumns, Rows: candidateRows, Order: candidateOrder},
		{Name: "excluded.csv", Format: CSV, Columns: []string{"value", "reason"}, Rows: excludedRows},
		{Name: "subdomains.txt", Format: TXT, Rows: inScopeHostRows(false)},
		{Name: "resolutions.csv", Format: CSV, Columns: []string{"name", "type", "value", "source", "self_hosted", "historical_first_seen", "historical_last_seen"}, Rows: resolutionRows},
		{Name: "unresolved.txt", Format: TXT, Rows: unresolvedRows},
		{Name: "wildcard-excluded.txt", Format: TXT, Rows: inScopeHostRows(true)},
		{Name: "ips.csv", Format: CSV, Columns: []string{"ip", "asn", "owner", "provider", "service", "in_scope", "port_eligible", "hostnames", "registrant", "registrant_netblock", "registry", "srv_ports"}, Rows: ipRows},
		{Name: "provider-hosts.csv", Format: CSV, Columns: []string{"hostname", "provider", "service", "evidence", "cname", "resolves"}, Rows: providerHostRows},
		{Name: "web-services.csv", Format: CSV, Columns: webServiceColumns, Rows: webServiceRows},
		{Name: "urls.csv", Format: CSV, Columns: []string{"url", "host", "status", "found_by"}, Rows: urlRows},
		{Name: "open-ports.csv", Format: CSV, Columns: openPortColumns, Rows: openPortRows},
		{Name: "email-posture.csv", Format: CSV, Columns: emailPostureColumns, Rows: emailPostureRows},
		{Name: "third-parties.csv", Format: CSV, Columns: thirdPartyColumns, Rows: thirdPartyRows},
		{Name: "code-mentions.csv", Format: CSV, Columns: codeMentionColumns, Rows: codeMentionRows},
	}
	for _, f := range findings.Files() {
		files = append(files, findingsFile(f))
	}
	files = append(files, File{Name: "changes.csv", Format: CSV, Columns: changeColumns, Rows: changeRows, Order: changeOrder})
	return files
}

var webServiceColumns = []string{"url", "host", "port", "scheme", "status", "title", "server", "technologies", "redirect",
	"final_url", "tls_subject", "tls_sans", "tls_issuer", "tls_expiry", "tls_version", "tls_cipher", "tls_trust",
	"hsts", "insecure_cookies", "directory_listing", "version_disclosure", "analytics_ids", "pixel_ids", "favicon_hash", "copyright"}

// webServiceCells are a web service's cells, in webServiceColumns order. p is
// the service's posture evidence, or nil for a service probed before posture
// was recorded (its posture cells are blank until httpprobe is redone). ids are
// the service's identifier cells (see identifierCells).
func webServiceCells(key string, a kinds.WebServiceAttrs, p *kinds.WebPostureAttrs, ids [4]string) []string {
	cells := []string{key, a.Host, strconv.Itoa(a.Port), a.Scheme, strconv.Itoa(a.Status), a.Title, a.Server, a.Technologies,
		a.Redirect, a.FinalURL, a.TLSSubject, a.TLSSANs, a.TLSIssuer, a.TLSExpiry, a.TLSVersion, a.TLSCipher, kinds.TLSTrust(a)}
	if p == nil {
		cells = append(cells, "", "", "", "")
	} else {
		hsts := ""
		if p.HSTS != nil {
			hsts = yesNo(*p.HSTS)
		}
		cells = append(cells, hsts, insecureCookies(*p), yesNo(p.DirectoryListing), p.VersionDisclosure)
	}
	return append(cells, ids[:]...)
}

// identifierCells are, for each web service, the analytics_ids, pixel_ids,
// favicon_hash and copyright cells: the values of its current web_identifier
// records of that type, sorted and joined with ";". A record that is not current
// has no attributes, so a service whose identifiers are all gone has blank cells.
func identifierCells(s Snapshot) map[string][4]string {
	cols := map[string]int{kinds.IdentifierAnalytics: 0, kinds.IdentifierPixel: 1, kinds.IdentifierFavicon: 2, kinds.IdentifierCopyright: 3}
	values := map[string]*[4][]string{}
	vis := s.vis()
	for _, r := range s.of(kinds.WebIdentifier) {
		if !r.Current || !vis.Shown(kinds.WebIdentifier, r) {
			continue
		}
		a := kinds.WebIdentifier.Attrs(r)
		col, ok := cols[a.Type]
		if !ok {
			continue
		}
		if values[a.Service] == nil {
			values[a.Service] = &[4][]string{}
		}
		values[a.Service][col] = append(values[a.Service][col], a.Value)
	}
	out := make(map[string][4]string, len(values))
	for service, v := range values {
		var cells [4]string
		for i := range cells {
			slices.Sort(v[i])
			cells[i] = strings.Join(slices.Compact(v[i]), ";")
		}
		out[service] = cells
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// insecureCookies lists each cookie lacking a flag with the flags it lacks:
// "sid(secure)(httponly)", ";"-joined, sorted by name.
func insecureCookies(p kinds.WebPostureAttrs) string {
	lacks := map[string]string{}
	for n := range strings.SplitSeq(p.CookiesNoSecure, ";") {
		lacks[n] += "(secure)"
	}
	for n := range strings.SplitSeq(p.CookiesNoHTTPOnly, ";") {
		lacks[n] += "(httponly)"
	}
	delete(lacks, "")
	var out []string
	for _, n := range slices.Sorted(maps.Keys(lacks)) {
		out = append(out, n+lacks[n])
	}
	return strings.Join(out, ";")
}

// vis is the snapshot's Visibility. Render always sets one; a file's Rows
// called on its own (in a test) gets a new one.
func (s Snapshot) vis() *kinds.Visibility {
	if s.Vis != nil {
		return s.Vis
	}
	return kinds.NewVisibility(s.Scope, s.Inv)
}

func webServiceRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	// A posture record belongs to the service of the same key and is read while it is current.
	posture := map[string]*kinds.WebPostureAttrs{}
	for _, r := range s.of(kinds.WebPosture) {
		if r.Current {
			a := kinds.WebPosture.Attrs(r)
			posture[r.Key] = &a
		}
	}
	ids := identifierCells(s)
	for _, r := range s.of(kinds.WebService) {
		if vis.Shown(kinds.WebService, r) {
			rows = append(rows, recordRow(r, webServiceCells(r.Key, kinds.WebService.Attrs(r), posture[r.Key], ids[r.Key])...))
		}
	}
	return rows
}

func urlRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.URL) {
		if vis.Shown(kinds.URL, r) {
			a, status := kinds.URL.Attrs(r), ""
			if a.Status != 0 { // fetched
				status = strconv.Itoa(a.Status)
			}
			rows = append(rows, recordRow(r, r.Key, a.Host, status, strings.Join(r.Stages, ",")))
		}
	}
	return rows
}

func scopeRows(s Snapshot) []Row {
	var rows []Row
	for _, in := range s.Inputs {
		if in.Kind == "exclude" {
			continue
		}
		rows = append(rows, Row{Cells: []string{in.Kind, in.Value, "input"}, Current: true, FirstSeen: in.AddedAt, LastSeen: s.Today})
	}
	for _, r := range s.of(kinds.Netblock) {
		if src, ok := s.ASNNetblocks[r.Key]; ok {
			rows = append(rows, recordRow(r, "netblock", r.Key, src))
		}
	}
	return rows
}

// of is the records of a kind, current or not.
func (s Snapshot) of(k kinds.Named) []store.Record { return s.Records[k.Name()] }

func recordRow(r store.Record, cells ...string) Row {
	return Row{Cells: cells, Current: r.Current, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
}

// excludedRows lists the values the summary counts as excluded, once each. A
// value carried by several records is listed from the first current one, so
// the row is current exactly when the summary counts it.
func excludedRows(s Snapshot) []Row {
	var rows []Row
	at := map[string]int{} // value -> index in rows
	vis := s.vis()
	for _, kind := range []kinds.Named{kinds.Root, kinds.Hostname, kinds.ExcludedKind} {
		for _, r := range s.of(kind) {
			if vis.Category(kind, r) != kinds.Excluded {
				continue
			}
			i, seen := at[r.Key]
			if seen && (rows[i].Current || !r.Current) {
				continue
			}
			reason := s.Scope.ClassifyHost(r.Key).Reason
			if kind.Name() == kinds.ExcludedKind.Name() {
				reason = kinds.ExcludedKind.Attrs(r).Reason
			}
			row := recordRow(r, r.Key, reason)
			if seen {
				rows[i] = row
			} else {
				at[r.Key] = len(rows)
				rows = append(rows, row)
			}
		}
	}
	return rows
}

// inScopeHostRows lists the in-scope hostnames that exist only because of a
// wildcard (wildcard-excluded.txt), or all the others (subdomains.txt).
func inScopeHostRows(wildcardOnly bool) func(Snapshot) []Row {
	return func(s Snapshot) []Row {
		var rows []Row
		wo := s.Inv.WildcardOnly()
		for _, r := range s.of(kinds.Hostname) {
			if wo[r.Key] == wildcardOnly && s.Scope.HostInScope(r.Key) {
				rows = append(rows, recordRow(r, r.Key))
			}
		}
		return rows
	}
}

func unresolvedRows(s Snapshot) []Row {
	var rows []Row
	for _, r := range s.of(kinds.Unresolved) {
		rows = append(rows, recordRow(r, r.Key))
	}
	return rows
}

// resolutionRows merges nyx's own DNS answers with the records third parties
// reported, by key. source is "resolve" for a record nyx's lookup holds,
// the reporting source for a claim alone, and both, joined with ";", when both
// hold it. A record nyx holds takes its dates and currency from nyx. A
// historical address (type A-historical or AAAA-historical, source dnshistory)
// follows, with the dates its source gave in the last two columns, which every
// other row leaves blank. It is a kind of its own, so it never shares a key
// with an answer.
func resolutionRows(s Snapshot) []Row {
	var rows []Row
	at := map[string]int{}
	for _, r := range s.of(kinds.Resolution) {
		a := kinds.Resolution.Attrs(r) // one no longer current has its attributes from its key
		// self_hosted is on a current NS row only: a row no longer current has lost its
		// attributes, and says nothing of who runs the server today.
		selfHosted := ""
		if a.Type == "NS" && r.Current {
			selfHosted = yesNo(s.Inv.SelfHosted(a.Value, s.Scope))
		}
		at[r.Key] = len(rows)
		rows = append(rows, recordRow(r, a.Name, a.Type, a.Value, "resolve", selfHosted, "", ""))
	}
	for _, r := range s.of(kinds.DNSClaim) {
		a := kinds.DNSClaim.Attrs(r)
		if i, ok := at[r.Key]; ok {
			rows[i].Cells[3] += ";" + a.Source
			continue
		}
		rows = append(rows, recordRow(r, a.Name, a.Type, a.Value, a.Source, "", "", ""))
	}
	vis := s.vis()
	for _, r := range s.of(kinds.HistoricalAddress) {
		if r.Current && !vis.Shown(kinds.HistoricalAddress, r) {
			continue
		}
		a := kinds.HistoricalAddress.Attrs(r)
		rows = append(rows, recordRow(r, a.Host, a.Type+"-historical", a.Addr, "dnshistory", "", a.FirstSeen, a.LastSeen))
	}
	return rows
}

// derivedRows builds rows computed from the inventory. Each is dated by the
// record of kind k whose key is the row's first cell, or today if there is none.
func derivedRows(s Snapshot, k kinds.Named, cells [][]string) []Row {
	seen := map[string]store.Record{}
	for _, r := range s.of(k) {
		seen[r.Key] = r
	}
	rows := make([]Row, 0, len(cells))
	for _, c := range cells {
		row := Row{Cells: c, Current: true, FirstSeen: s.Today, LastSeen: s.Today}
		if rec, ok := seen[c[0]]; ok {
			row.FirstSeen, row.LastSeen = rec.FirstSeen, rec.LastSeen
		}
		rows = append(rows, row)
	}
	return rows
}

func ipRows(s Snapshot) []Row {
	var cells [][]string
	for _, ir := range s.Inv.IPRows(s.Scope) {
		asn := ""
		if ir.ASN != 0 {
			asn = fmt.Sprintf("AS%d", ir.ASN)
		}
		cells = append(cells, []string{ir.IP.String(), asn, ir.Owner, ir.Provider, ir.Service,
			fmt.Sprint(ir.InScope), fmt.Sprint(ir.PortEligible), strings.Join(ir.Hostnames, ";"),
			ir.Registrant, ir.RegistrantNetblock, ir.Registry, joinPorts(ir.SRVPorts)})
	}
	return derivedRows(s, kinds.IP, cells)
}

// joinPorts writes ports as one `;`-joined cell.
func joinPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ";")
}

func providerHostRows(s Snapshot) []Row {
	var cells [][]string
	for _, ph := range s.Inv.ProviderHosts(s.Scope) {
		cells = append(cells, []string{ph.Hostname, ph.Provider, ph.Service, ph.Evidence, ph.CNAME, fmt.Sprint(ph.Resolves)})
	}
	return derivedRows(s, kinds.Hostname, cells)
}
