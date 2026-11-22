# End-of-life software

From versions nyx already captured, with no further request, it reports software whose release
cycle is past the end of security support, or about to be, in `risk-eol-software.csv`. The versions
come from two places only: the `Name:version` technologies Wappalyzer reads from each in-scope web
service (the `technologies` column of `web-services.csv`), and the banner of each open SSH, FTP or
SMTP port (the `banner` of `open-ports.csv`, nyx's own, or Shodan's for a port only Shodan reports).
Neither the `Server` and `X-Powered-By` text of `version_disclosure` nor any other source is read,
and no CVE is matched.

The dates are embedded in the binary, as [endoflife.date](https://endoflife.date) records them: the
end of security support of each release cycle (its `eol` date), for these products, which are the
ones it tracks that nyx can version (the names are Wappalyzer's, or the banner's for the last
three): Apache HTTP Server, Nginx, PHP, Apache Tomcat, Jetty, Spring, Ruby on Rails, Django,
Laravel, Symfony, Drupal, WordPress, Joomla, Magento, Node.js, Express, Python, Ruby, jQuery,
jQuery UI, Bootstrap, AngularJS, Angular, OpenSSL, MySQL, MariaDB, PostgreSQL, Elasticsearch,
Kibana, Grafana, GitLab, Nextcloud, MediaWiki, phpMyAdmin, Moodle, RoundCube, Zabbix, Vue.js,
React, Ember.js, Next.js, Jenkins, Atlassian Bitbucket, Artifactory (and Artifactory Web Server),
Discourse, Concrete CMS, Backdrop, Umbraco, Shopware, SonarQube, Gerrit, YouTrack, Apache APISIX,
Kong, Neos CMS, Perl, Lua, CouchDB, Subversion, Jekyll, Varnish (Vinyl Cache), Postfix,
Exim and ProFTPD. The data was taken on **2026-11-17**; a run more than twelve months after that
date prints one WARN line saying so (with no flag), and still uses the data. `make eol-data`
downloads it again (it needs `curl` and `jq`) for review and commit.

A version belongs to the release cycle named by its first one, two or three dotted numbers (as
the product names its cycles, so `7.4.3` is PHP 7.4 and `1.3.5e` is ProFTPD 1.3.5). A version that
matches no cycle, a cycle with no end announced, and a technology with no version give no finding.

- `eol` (medium): the cycle's end date is on or before the run date (UTC). A cycle endoflife.date
  lists as ended with no date (`jQuery` 1.x) is `eol` too, with an empty `end_date`.
- `eol-approaching` (low): the end date is after the run date and within `eol_warn_days`
  (`--eol-warn-days`, default 90, at least 0; 0 turns this type off and leaves `eol`).

A version carrying a distribution suffix (`Debian`, `Ubuntu`, `CentOS`, `+deb`, `~bpo` and the
like) is one step lower, because a distribution backports fixes under the upstream version: `eol`
becomes low, with `distribution build` in the `detail`. Wappalyzer reports a header's version
without the suffix, so for a web service the `Server` or `X-Powered-By` value that carries the
version is read for it (`Apache/2.4.41 (Ubuntu)`, `PHP/7.4.3-4ubuntu2.19`). A version known only from a Shodan port
report is one step lower too, with `confirmed` `no` (as for [Shodan per address](sources.md#shodan-per-address)),
and becomes the full severity once nyx's own banner names it. Each end-of-life product on a service
or port is its own row.

`risk-eol-software.csv` has `severity`, `target` (the service URL, or `ip:port`), `hostnames` (the
in-scope names behind the address, for a port), `type`, `product`, `version`, `end_date`, `seen`
(`web` or `banner`) and `confirmed`. Findings are derived on every run from the latest probe and
banner records and the run date, so one can appear with no new contact when the date passes an end
date, and under `--passive` they come from records kept by earlier runs. A finding goes not current
when `--redo httpprobe` or `--redo ports` no longer shows that version. Only in-scope web services
and port-eligible addresses are assessed, as for other findings.

`open-ports.csv` has `product` and `version` columns, read from the banner shown in its `banner`
column when it is one of OpenSSH, Dropbear, ProFTPD, vsftpd, Pure-FTPd, Postfix, Exim, Sendmail,
Microsoft IIS FTP or Microsoft Exchange (SMTP); any other banner leaves both empty, and a banner that
names no version leaves `version` empty. The columns are worked out when the file is written, so an
earlier engagement has them after its next run, with no new contact. OpenSSH, Dropbear, vsftpd,
Pure-FTPd, Sendmail, IIS FTP and Exchange are recognised but not assessed: endoflife.date does not
track the first five, and an Exchange banner's version is a build number that no cycle names.
