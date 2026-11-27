package risk

import (
	"context"
	"encoding/xml"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/cloudstorage"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Storage checks referenced and guessed cloud resources through public provider endpoints,
// including passive runs. It lists anonymously and HEADs one object without downloading object
// contents.
type Storage struct{}

// NewStorage returns the storage procedure.
func NewStorage() *Storage { return &Storage{} }

func (*Storage) Name() string         { return "storage" }
func (*Storage) Contact() run.Contact { return run.ThirdParty }
func (*Storage) Sources() []string {
	return []string{"s3.amazonaws.com", "s3.*.amazonaws.com", "storage.googleapis.com", "*.blob.core.windows.net"}
}
func (*Storage) Configured(run.Env) (bool, string) { return true, "" }

type storageInput struct {
	kind                              string // bucket, account, container or object
	provider, name, container, object string
	region                            string // S3: where the bucket's listing said it lives
}

var (
	safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$`)
	// safeContainer follows Azure's container naming rules (3-63 lower-case letters, digits and
	// single hyphens, starting and ending with a letter or digit) plus the system containers, so
	// a referenced name Azure rejects with 400 is not asked on every run.
	safeContainer = regexp.MustCompile(`^(?:\$root|\$web|\$logs|[a-z0-9][a-z0-9-]{1,61}[a-z0-9])$`)
	regionRE      = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// Jobs picks up resources discovered by earlier passes, such as containers in newly confirmed
// accounts or objects found in bucket listings.
func (*Storage) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		emit := func(key string, in storageInput) bool { return yield(run.Job{Key: key, Input: in}, nil) }
		refs := v.StorageRefs()
		if !bucketJobs(v, refs, emit) || !containerJobs(v, refs, emit) {
			return
		}
		objectJobs(v, refs, emit)
	}
}

// storageEmit yields one job, reporting whether to go on.
type storageEmit func(key string, in storageInput) bool

// bucketJobs prioritises referenced buckets/accounts before root- and organisation-based
// guesses. Its result allows early enumeration stop.
func bucketJobs(v run.View, refs []cloudstorage.Reference, emit storageEmit) bool {
	bucket := func(provider, name string) bool {
		if !safeName.MatchString(name) {
			return true
		}
		if provider == cloudstorage.Azure {
			return emit(cloudstorage.AccountKey(name), storageInput{kind: "account", provider: provider, name: name})
		}
		return emit(cloudstorage.Key(provider, name, ""), storageInput{kind: "bucket", provider: provider, name: name})
	}
	for _, r := range refs {
		if !bucket(r.Provider, r.Name) {
			return false
		}
	}
	in := v.Inputs()
	for _, g := range cloudstorage.InputGuesses(in.Roots, in.Orgs, v.Settings().Storage.MaxNames) {
		if !bucket(g.Provider, g.Name) {
			return false
		}
	}
	return true
}

// containerJobs combines fixed container names and references for known existing Azure
// accounts, allowing early enumeration stop.
func containerJobs(v run.View, refs []cloudstorage.Reference, emit storageEmit) bool {
	for _, acct := range existingAccounts(v) {
		for _, c := range accountContainers(acct, refs) {
			if safeContainer.MatchString(c) && !strings.Contains(c, "--") && !emit(cloudstorage.Key(cloudstorage.Azure, acct, c), storageInput{kind: "container", provider: cloudstorage.Azure, name: acct, container: c}) {
				return false
			}
		}
	}
	return true
}

// existingAccounts are the Azure accounts known to exist.
func existingAccounts(v run.View) []string {
	var accounts []string
	for _, rec := range v.Records(kinds.StorageAccount) {
		if e := kinds.StorageAccount.Attrs(rec).Exists; e != nil && *e {
			accounts = append(accounts, rec.Key)
		}
	}
	return accounts
}

// accountContainers prioritises fixed names before additional referenced containers.
func accountContainers(acct string, refs []cloudstorage.Reference) []string {
	containers := slices.Clone(cloudstorage.AzureContainers)
	for _, r := range refs {
		if r.Provider == cloudstorage.Azure && r.Name == acct && r.Container != "" && !slices.Contains(containers, r.Container) {
			containers = append(containers, r.Container)
		}
	}
	return containers
}

// objectJobs deduplicates and sorts HEAD requests for the first listed and referenced objects
// of existing buckets.
func objectJobs(v run.View, refs []cloudstorage.Reference, emit storageEmit) {
	existing := map[string]storageInput{} // object inputs without the object
	objs := map[string]storageInput{}
	for _, rec := range v.Records(kinds.Storage) {
		a := kinds.Storage.Attrs(rec)
		if a.Exists == nil || !*a.Exists {
			continue
		}
		b := storageInput{kind: "object", provider: a.Provider, name: a.Name, container: a.Container, region: a.Region}
		existing[rec.Key] = b
		if len(a.FirstKeys) > 0 && a.FirstKeys[0] != "" {
			b.object = a.FirstKeys[0]
			objs[rec.Key+"/"+b.object] = b
		}
	}
	for _, r := range refs {
		key := cloudstorage.Key(r.Provider, r.Name, r.Container)
		if b, ok := existing[key]; ok && r.Object != "" {
			b.object = r.Object
			objs[key+"/"+r.Object] = b
		}
	}
	for _, key := range slices.Sorted(maps.Keys(objs)) {
		if !emit(strings.Replace(key, "|", "-obj|", 1), objs[key]) {
			return
		}
	}
}

// Run performs one job.
func (s *Storage) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(storageInput)
	var obs []run.Observation
	var err error
	switch in.kind {
	case "account":
		obs, err = account(ctx, e, in)
	case "object":
		obs, err = object(ctx, e, in)
	default:
		obs, err = list(ctx, e, in)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	return obs, nil
}

// account looks the account's host up in DNS: a name that exists is a storage account.
func account(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	res, err := e.DNS.Query(ctx, in.name+".blob.core.windows.net", egress.TypeA)
	if err != nil {
		return nil, err
	}
	var exists bool
	switch res.RCode {
	case egress.RCodeSuccess:
		exists = len(res.Answers) > 0 || len(res.CNAMEs) > 0
	case egress.RCodeNXDomain:
	default:
		return nil, fmt.Errorf("DNS rcode %d", res.RCode)
	}
	return []run.Observation{kinds.StorageAccount.Obs(in.name, kinds.StorageAccountAttrs{Exists: &exists})}, nil
}

// escapePath escapes each segment of an object key.
func escapePath(parts ...string) string {
	var segs []string
	for _, p := range parts {
		for s := range strings.SplitSeq(p, "/") {
			segs = append(segs, url.PathEscape(s))
		}
	}
	return "/" + strings.Join(segs, "/")
}

// storageURL formats bucket/container or object endpoints. S3 uses regional path-style URLs.
func storageURL(in storageInput, region string, object ...string) string {
	host, base := "s3.amazonaws.com", in.name
	switch in.provider {
	case cloudstorage.GCS:
		host = "storage.googleapis.com"
	case cloudstorage.Azure:
		host, base = in.name+".blob.core.windows.net", in.container
	default:
		if region != "" {
			host = "s3." + region + ".amazonaws.com"
		}
	}
	return "https://" + host + escapePath(append([]string{base}, object...)...)
}

// listURL is where a bucket or container is listed anonymously.
func listURL(in storageInput, region string) string {
	switch in.provider {
	case cloudstorage.GCS:
		return storageURL(in, region) + "?max-keys=1000"
	case cloudstorage.Azure:
		return storageURL(in, region) + "?restype=container&comp=list&maxresults=1000"
	}
	return storageURL(in, region) + "?list-type=2&max-keys=1000"
}

// objectURL is the URL of an object, for a HEAD.
func objectURL(in storageInput, region string) string { return storageURL(in, region, in.object) }

// request sends one request and, for S3, follows a 301 to the bucket's region once.
func request(ctx context.Context, e egress.Clients, method string, in storageInput, build func(region string) string) (egress.ThirdPartyResponse, string, error) {
	region := in.region
	resp, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: method, URL: build(region)})
	if err != nil {
		return resp, region, err
	}
	if in.provider == cloudstorage.S3 && (resp.Status == 301 || resp.Status == 307) {
		r := redirectRegion(resp)
		if r == region || !regionRE.MatchString(r) {
			return resp, region, fmt.Errorf("redirect to an unusable region %q", r)
		}
		region = r
		resp, err = e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: method, URL: build(region)})
	}
	return resp, region, err
}

// s3RegionHost recognises dotted, hyphenated and dual-stack regional endpoints.
var s3RegionHost = regexp.MustCompile(`(?:^|\.)s3[.-](?:dualstack\.)?([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazonaws\.com$`)

// redirectRegion reads S3's region header, Location host or XML Endpoint in that order,
// covering new-bucket redirects with no region header.
func redirectRegion(resp egress.ThirdPartyResponse) string {
	if r := resp.HeaderValue("X-Amz-Bucket-Region"); r != "" {
		return r
	}
	var hosts []string
	if loc := resp.HeaderValue("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	var body struct {
		Endpoint string `xml:"Endpoint"`
	}
	if xml.Unmarshal(resp.Body, &body) == nil && body.Endpoint != "" {
		hosts = append(hosts, body.Endpoint)
	}
	for _, h := range hosts {
		if m := s3RegionHost.FindStringSubmatch(strings.ToLower(h)); m != nil {
			return m[1]
		}
	}
	return ""
}

type listing struct {
	Truncated  string   `xml:"IsTruncated"`
	Keys       []string `xml:"Contents>Key"`
	Blobs      []string `xml:"Blobs>Blob>Name"`
	NextMarker string   `xml:"NextMarker"`
}

// list records anonymous existence/listability, object counts and initial keys.
func list(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	resp, region, err := request(ctx, e, "GET", in, func(r string) string { return listURL(in, r) })
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		return nil, fmt.Errorf("listing larger than the 10 MiB limit")
	}
	attrs := kinds.StorageAttrs{Provider: in.provider, Name: in.name, Container: in.container}
	yes, no := true, false
	body := string(resp.Body)
	switch {
	case resp.Status == 200:
		var l listing
		if err := xml.Unmarshal(resp.Body, &l); err != nil {
			return nil, fmt.Errorf("unreadable listing: %w", err)
		}
		keys := slices.Concat(l.Keys, l.Blobs)
		count := fmt.Sprint(len(keys))
		if strings.EqualFold(l.Truncated, "true") || l.NextMarker != "" {
			count += "+"
		}
		attrs.Exists, attrs.Listable, attrs.ObjectCount, attrs.FirstKeys = &yes, &yes, count, slices.Clone(keys[:min(5, len(keys))])
	case resp.Status == 404 && (strings.Contains(body, "NoSuchBucket") || strings.Contains(body, "ContainerNotFound")):
		attrs.Exists = &no
	case resp.Status == 401 || resp.Status == 403:
		attrs.Exists, attrs.Listable = &yes, &no
	case in.provider == cloudstorage.Azure && (resp.Status == 404 && strings.Contains(body, "ResourceNotFound") ||
		resp.Status == 409 && strings.Contains(body, "PublicAccessNotPermitted")):
		// Azure uses the same anonymous response for private and missing containers.
		// Keep existence unknown so privacy cannot be mistaken for a claimable
		// resource.
		attrs.Listable = &no
	default:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	}
	attrs.Region = region
	return []run.Observation{kinds.Storage.Obs(cloudstorage.Key(in.provider, in.name, in.container), attrs)}, nil
}

// object sends one anonymous HEAD for an object: it is public if that succeeds.
func object(ctx context.Context, e egress.Clients, in storageInput) ([]run.Observation, error) {
	resp, region, err := request(ctx, e, "HEAD", in, func(r string) string { return objectURL(in, r) })
	if err != nil {
		return nil, err
	}
	var public bool
	switch resp.Status {
	case 200:
		public = true
	case 401, 403, 404:
	default:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	}
	bucket := cloudstorage.Key(in.provider, in.name, in.container)
	return []run.Observation{kinds.StorageObject.Obs(bucket+"/"+in.object, kinds.StorageObjectAttrs{
		Bucket: bucket, Provider: in.provider, Name: in.name, Container: in.container, Object: in.object,
		Public: public, URL: objectURL(in, region),
	})}, nil
}
