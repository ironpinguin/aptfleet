# updates_report

Zeigt die anstehenden deb-Updates auf einem oder mehreren Ubuntu-Hosts, zusammen mit den
Security-Infos dazu:

- **Updates pro Host** mit Security-Kennzeichnung und den CVEs, die das Update behebt
  (aus dem Changelog), inklusive Ubuntu-Priorität (`critical`, `high`, …)
- **KEV-Markierung:** CVEs, die laut [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  aktiv ausgenutzt werden, sind als `KEV` hervorgehoben
- **Offene Lücken ohne Fix:** installierte Pakete mit CVEs, für die es noch kein Update
  gibt. Angezeigt werden nur CVEs auf KEV oder mit Priorität `high`/`critical`
  (Quelle: Ubuntu-OVAL-Daten)
- **Kernel:** veraltete laufende Kernel (Reboot nötig) und überholte Paketversionen
- optional **Neu auf KEV:** die zuletzt in den KEV-Katalog aufgenommenen CVEs

Auf den Hosts wird nur gelesen. Pro Host gibt es eine SSH-Session. Das Remote-Skript
kommt per stdin, auf dem Host wird nichts abgelegt.

## Voraussetzungen

**Lokal** (wo das Skript läuft):

- Python ≥ 3.9, nur Standardbibliothek, kein `pip install` nötig
- `ssh`-Client mit Key-Login auf die Hosts. Das Skript nutzt `BatchMode=yes`, es fragt
  also nie nach einem Passwort
- Internetzugang zu `ubuntu.com`, `security-metadata.canonical.com` und `cisa.gov`.
  Ohne diese Quellen läuft der Report trotzdem, nur mit weniger Infos (siehe Exit-Code 3)

**Auf den Hosts:**

- Ubuntu mit `bash`, `apt`, `dpkg-query`, `timeout` (Standardinstallation)
- Für das `apt-get update` vor der Prüfung: `sudo` ohne Passwort für den SSH-User.
  Ohne das mit `--no-refresh` aufrufen; dann gelten die vorhandenen Paketlisten

## Installation

Das Verzeichnis `updates_report/` irgendwohin kopieren und fertig:

```bash
cp -r updates_report ~/tools/
~/tools/updates_report/check_updates.py --help
```

## Hosts festlegen

Es gibt zwei Betriebsarten.

### 1. Ad hoc: `--host` + `--user`

Hosts direkt angeben. Es gilt die normale `~/.ssh/config` (Aliase, Keys, `ProxyJump`):

```bash
./check_updates.py --user admin --host web1.example.com --host 10.0.0.12
./check_updates.py --user ansiadm --host mein-alias-aus-ssh-config
```

### 2. Inventory im Elternverzeichnis

Ohne `--user` liest das Skript zwei Dateien aus dem Verzeichnis **über** `updates_report/`:

```
<projekt>/
├── virtualhosts                          # Inventory
├── ssh_config_rootserver_ansible.conf    # SSH-Config, wird per ssh -F genutzt
└── updates_report/
    └── check_updates.py
```

`virtualhosts` (Ansible-INI-Format, ein Host pro Zeile; `#`-Zeilen und `[gruppen]`
werden ignoriert):

```ini
[ubuntu]
host-a
host-b
#host-c   (wird übersprungen)
```

Die SSH-Config enthält die passenden `Host`-Blöcke:

```
Host host-a
  HostName 192.0.2.10
  User ansiadm
  IdentityFile ~/.ssh/ansible_ed25519

Host host-b
  HostName 10.0.0.5
  User ansiadm
  IdentityFile ~/.ssh/ansible_ed25519
  ProxyJump host-a
```

Dann prüft ein Aufruf alle Hosts:

```bash
./check_updates.py
./check_updates.py --host host-b      # nur einer (muss in virtualhosts stehen)
```

Wenn `virtualhosts` fehlt, endet das Skript mit Exit-Code 2 und weist auf
`--host`/`--user` hin.

## Aufruf und Optionen

```bash
./check_updates.py [Optionen]
```

| Option | Wirkung |
|---|---|
| `--host NAME` | nur diesen Host prüfen, mehrfach möglich. Ohne `--user` muss der Name in `virtualhosts` stehen |
| `--user NAME` | SSH-User. Nutzt die `--host`-Angaben direkt, ohne `virtualhosts` und ohne Repo-SSH-Config |
| `--security-only` | nur Security-Updates anzeigen |
| `--details` | neue Changelog-Einträge der Updates anzeigen. Holt auch CVE-Infos für offene Lücken |
| `--package NAME` | nur dieses Binärpaket, mehrfach möglich |
| `--no-refresh` | kein `apt-get update` vorher, braucht dann kein sudo |
| `--timeout SEKUNDEN` | Timeout pro Host (Default 120) |
| `--verbose` | nicht parsebare Zeilen und Pakete ohne Ubuntu-Herkunft (PPAs, Fremd-Repos) anzeigen |
| `--kev-recent [TAGE]` | in den letzten TAGE (Default 7) neu auf KEV aufgenommene CVEs auflisten |

Beispiele:

```bash
./check_updates.py --security-only
./check_updates.py --host host-a --details
./check_updates.py --package openssh-server --package sudo
./check_updates.py --kev-recent 14
```

Bis zu 6 Hosts werden parallel abgefragt. Die Ausgabe ist farbig, wenn sie in ein
Terminal geht; bei Umleitung in eine Datei oder Pipe ist sie unformatiert.

## Exit-Codes

Damit lässt sich der Report in Cron oder Monitoring einbinden:

| Code | Bedeutung |
|---|---|
| `0` | nichts Dringendes: keine Security-Updates, keine offene KEV-Lücke |
| `1` | Security-Updates stehen an **oder** eine offene KEV-Lücke ohne Fix existiert |
| `2` | mindestens ein Host nicht erreichbar, oder Aufruf-/Inventory-Fehler |
| `3` | Prüfung unvollständig: KEV-Liste oder Ubuntu-Schwachstellendaten nicht abrufbar bzw. Host-Daten fehlen |

Bei mehreren zutreffenden Codes gilt die Reihenfolge 2 vor 3 vor 1.

Beispiel Cron mit Mail nur bei Handlungsbedarf:

```cron
0 7 * * *  cd ~/tools/updates_report && ./check_updates.py --security-only > /tmp/updates.txt; [ $? -ne 0 ] && mail -s "Updates" admin@example.com < /tmp/updates.txt
```

## Datenquellen und Cache

| Quelle | Wofür | Cache | gültig |
|---|---|---|---|
| `ubuntu.com/security/cves/<id>.json` | Priorität/Beschreibung einzelner CVEs | `~/.cache/updates_report/cves.json` | 7 Tage |
| CISA KEV-Feed (JSON) | aktiv ausgenutzte CVEs | `~/.cache/updates_report/kev.json` | 24 h |
| Ubuntu-OVAL (`security-metadata.canonical.com`) | offene Lücken je Release | `~/.cache/updates_report/oval-<codename>.json` | 24 h |

Ist eine Quelle nicht erreichbar, wird ein vorhandener älterer Cache genutzt. Der Report
gibt dann einen Hinweis mit dem Datenstand aus. Ohne jeden Cache fehlt der jeweilige
Teil, und der Exit-Code ist 3. Cache leeren: `rm -rf ~/.cache/updates_report`.

## Tests

Die Tests laufen ohne echte Hosts und ohne Netz:

```bash
cd updates_report
python3 -m unittest discover -s tests -t .
```

## Aufbau

| Modul | Aufgabe |
|---|---|
| `check_updates.py` | CLI, Inventory, Ablaufsteuerung, Exit-Code |
| `remote.py` | SSH-Aufruf und Remote-Skript (Abschnitte `===SECTION …===`) |
| `parsing.py` | Remote-Ausgabe in `HostReport`s zerlegen |
| `debversion.py` | Vergleich von Debian-Versionsnummern |
| `cve_info.py` | Ubuntu-CVE-API mit Cache |
| `kev.py` | CISA-KEV-Katalog mit Cache |
| `oval.py` | Ubuntu-OVAL-Feed laden und parsen |
| `vulns.py` | offene Lücken aus installierten Paketen und OVAL ermitteln |
| `render.py` | Textausgabe |
