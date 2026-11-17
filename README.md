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

Alternativ läuft das Skript mit `--local` direkt auf dem Server, ohne SSH, z. B. als
Cronjob mit Mailversand des HTML-Reports (siehe [Lokal per Cronjob](#lokal-per-cronjob)).

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
  Ohne sudo-Rechte mit `--no-refresh` aufrufen (siehe [Betrieb ohne sudo](#betrieb-ohne-sudo))

## Installation

Das Verzeichnis `updates_report/` irgendwohin kopieren und fertig:

```bash
cp -r updates_report ~/tools/
~/tools/updates_report/aptfleet.py --help
```

### Als .deb-Paket

Für die Server gibt es ein .deb, gebaut mit [nfpm](https://nfpm.goreleaser.com). Ist
`nfpm` nicht installiert, läuft es per Docker (`goreleaser/nfpm`). `make package` führt
vorher die Tests aus:

```bash
cd updates_report
make package                  # → dist/aptfleet-mail_1.0.0_all.deb
make package VERSION=1.1.0    # andere Version
```

Installieren:

```bash
scp dist/aptfleet-mail_1.0.0_all.deb server:
ssh server sudo apt install ./aptfleet-mail_1.0.0_all.deb
```

| Pfad | Inhalt |
|---|---|
| `/usr/bin/aptfleet` | ruft `aptfleet.py` auf, gleiche Optionen |
| `/usr/bin/aptfleet-mail` | Cron-Wrapper mit Mailversand (siehe [Lokal per Cronjob](#lokal-per-cronjob)) |
| `/usr/lib/aptfleet/` | Module und `cron/aptfleet-mail.sh` |
| `/etc/aptfleet/mail.env` | Konfiguration des Wrappers (conffile, Modus 0600) |
| `/etc/cron.d/aptfleet` | Cronjob, **auskommentiert**, bis `/etc/aptfleet/mail.env` angepasst ist |
| `/etc/aptfleet/` | optional `hosts.ini` und `ssh.conf` für den Betrieb per SSH (siehe [Defaults](#3-defaults)) |

Die beiden Dateien unter `/etc` sind conffiles. Eigene Änderungen bleiben bei Updates
erhalten, `apt purge aptfleet-mail` entfernt sie. Abhängigkeiten sind nur `python3` und
`bash`. Empfohlen werden `ca-certificates` und `openssh-client`, für den Mailversand
`curl` bzw. ein MTA.

## Hosts festlegen

Es gibt drei Wege per SSH. Für den eigenen Rechner ohne SSH gibt es `--local` (siehe
[Lokal per Cronjob](#lokal-per-cronjob)).

### 1. Ad hoc: `--host` + `--user`

Hosts direkt angeben. Es gilt die normale `~/.ssh/config` (Aliase, Keys, `ProxyJump`),
außer es wird `--ssh-config` angegeben:

```bash
./aptfleet.py --user admin --host web1.example.com --host 10.0.0.12
./aptfleet.py --user ansiadm --host mein-alias-aus-ssh-config
```

### 2. Eigenes Inventory: `--inventory` / `--ssh-config`

Inventory und SSH-Config können irgendwo liegen:

```bash
./aptfleet.py --inventory ~/etc/hosts.ini --ssh-config ~/etc/ssh_hosts.conf
./aptfleet.py --inventory ~/etc/hosts.ini     # SSH über ~/.ssh/config
```

Ohne `--ssh-config` wird die Default-Datei (siehe 3.) genutzt, falls sie existiert,
sonst die normale `~/.ssh/config`. Wie beide Dateien aussehen, steht unter
[Inventory-Format](#inventory-format) und [SSH-Config](#ssh-config).

### 3. Defaults

Ohne `--user` und `--inventory` liest das Skript zwei Dateien aus dem Verzeichnis
**über** `updates_report/`:

```
<projekt>/
├── virtualhosts                          # Inventory
├── ssh_config_rootserver_ansible.conf    # SSH-Config, wird per ssh -F genutzt
└── updates_report/
    └── aptfleet.py
```

Gibt es die Datei dort nicht (z. B. beim [.deb-Paket](#als-deb-paket)), gilt stattdessen
`/etc/aptfleet/hosts.ini` bzw. `/etc/aptfleet/ssh.conf`.

Dann prüft ein Aufruf alle Hosts:

```bash
./aptfleet.py
./aptfleet.py --host host-b      # nur einer (muss im Inventory stehen)
```

Fehlt das Inventory, endet das Skript mit Exit-Code 2 und nennt `--inventory` bzw.
`--host`/`--user`.

### Inventory-Format

Eine Textdatei im Stil eines Ansible-INI-Inventories. Ein bestehendes Ansible-Inventory
lässt sich in der Regel direkt verwenden:

```ini
# Kommentar
[ubuntu]
host-a
host-b              # Kommentar hinter dem Host ist erlaubt
#host-c             auskommentiert, wird übersprungen

[datenbanken]
db-1 ansible_host=10.0.0.20

[all:vars]
ansible_user=ansiadm   # wird ignoriert

[server:children]
ubuntu                 # Gruppennamen, keine Hosts – wird ignoriert
```

Regeln:

- Ein Host pro Zeile. Es zählt nur das **erste Wort** der Zeile.
- Leerzeilen und Zeilen, die mit `#` beginnen, werden übersprungen.
- Gruppenköpfe wie `[gruppe]` werden übersprungen. **Gruppen haben keine Bedeutung:** Es
  werden alle Hosts aus allen Gruppen geprüft. Nur einzelne Hosts lassen sich mit
  `--host` auswählen.
- Der Inhalt von `[gruppe:vars]` (Variablen) und `[gruppe:children]` (Gruppennamen) wird
  komplett übersprungen, ebenso jede Zeile, deren erstes Wort ein `=` enthält.
- Ansible-Variablen hinter dem Namen (`ansible_host=`, `ansible_user=` …) werden
  **ignoriert**. Der Name wird so an `ssh` übergeben. Er muss also ein Alias aus der
  SSH-Config, ein auflösbarer Hostname oder eine IP sein. Im Beispiel oben verbindet sich
  das Skript zu `db-1`, nicht zu `10.0.0.20`.
- Steht ein Host in mehreren Gruppen, wird er trotzdem nur einmal geprüft, an der
  Stelle seines ersten Auftretens.
- YAML-Inventories werden nicht unterstützt.

### SSH-Config

Eine normale OpenSSH-Config, die per `ssh -F` übergeben wird. Für jeden Namen aus dem
Inventory gibt es einen passenden `Host`-Block:

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

Mit `-F` liest `ssh` **nur** diese Datei, `~/.ssh/config` wird dann nicht ausgewertet.
Der Login muss ohne Passwort-Abfrage klappen (Key, ggf. ssh-agent), da das Skript mit
`BatchMode=yes` arbeitet. Testen: `ssh -F <config> host-a true`.

## Aufruf und Optionen

```bash
./aptfleet.py [Optionen]
```

| Option | Wirkung |
|---|---|
| `--local` | nur den eigenen Rechner prüfen, ohne SSH. Nicht kombinierbar mit `--host`, `--user`, `--inventory`, `--ssh-config` |
| `--host NAME` | nur diesen Host prüfen, mehrfach möglich. Ohne `--user` muss der Name im Inventory stehen |
| `--user NAME` | SSH-User. Nutzt die `--host`-Angaben direkt, ohne Inventory |
| `--inventory PFAD` | Inventory-Datei (Default: `../virtualhosts`, sonst `/etc/aptfleet/hosts.ini`) |
| `--ssh-config PFAD` | SSH-Config für `ssh -F` (Default: `../ssh_config_rootserver_ansible.conf` bzw. `/etc/aptfleet/ssh.conf`, falls vorhanden, sonst `~/.ssh/config`) |
| `--security-only` | nur Security-Updates anzeigen |
| `--details` | neue Changelog-Einträge der Updates anzeigen. Holt auch CVE-Infos für offene Lücken |
| `--package NAME` | nur dieses Binärpaket, mehrfach möglich |
| `--no-refresh` | kein `apt-get update` vorher, braucht dann kein sudo. Zeigt pro Host, wie alt die Paketlisten sind |
| `--timeout SEKUNDEN` | Timeout pro Host (Default 120) |
| `--verbose` | nicht parsebare Zeilen und Pakete ohne Ubuntu-Herkunft (PPAs, Fremd-Repos) anzeigen |
| `--kev-recent [TAGE]` | in den letzten TAGE (Default 7) neu auf KEV aufgenommene CVEs auflisten |
| `--html PFAD` | Report zusätzlich als HTML-Datei schreiben (siehe [HTML-Report](#html-report)) |
| `--no-progress` | keine Fortschrittsanzeige auf stderr (siehe unten) |

Beispiele:

```bash
./aptfleet.py --security-only
./aptfleet.py --host host-a --details
./aptfleet.py --package openssh-server --package sudo
./aptfleet.py --kev-recent 14
./aptfleet.py --details --html ~/reports/updates-$(date +%F).html
```

Bis zu 6 Hosts werden parallel abgefragt. Die Ausgabe ist farbig, wenn sie in ein
Terminal geht; bei Umleitung in eine Datei oder Pipe ist sie unformatiert.

**Fortschritt:** Läuft das Skript im Terminal, zeigt es auf stderr, was gerade passiert.
Eine Statuszeile nennt für jeden laufenden Host den aktuellen Schritt (`SSH-Verbindung`,
`apt-get update`, `Changelog 3/12: openssl`, …). Fertige Hosts und die folgenden Schritte
(KEV-Liste, Ubuntu-Schwachstellendaten, CVE-Infos) erscheinen als eigene Zeilen:

```text
» 3 Host(s) prüfen …
  ✓ [1/3] webserver-ansible fertig (14s)
  ✗ [2/3] pdf-ansible: ssh timeout nach 120s (120s)
  [2/3] rootserver-ansible: Changelog 4/9: linux-meta
```

Ist stderr kein Terminal (cron, `2>datei`), gibt es keine Fortschrittsanzeige. Mit
`--no-progress` lässt sie sich auch im Terminal abschalten. Der Report auf stdout ist in
beiden Fällen gleich.

### Terminal-Ausgabe

Bei mehreren Hosts steht oben eine Übersicht, darunter folgt pro Host ein Block mit den
Updates und den offenen Lücken:

```
Host                Ubuntu  Updates  Security  KEV-Fix  Offene Lücken
rootserver-ansible  24.04         5         3        2  1 (1 KEV)
pdf-ansible         FEHLER: ssh timeout nach 120s

━━ rootserver-ansible (Ubuntu 24.04) — 5 Updates, 3 Security, 1 offene Lücke ━━
   Updates:
      Paket       Version                                                        CVEs
 SEC  libssl3t64  3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5                          CVE-2025-9231, CVE-2025-9232 (high, KEV)
 SEC  openssl     3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5                          CVE-2025-9231, CVE-2025-9232 (high, KEV)
 SEC  libxml2     2.9.14+dfsg-1.3ubuntu3.1 → 2.9.14+dfsg-1.3ubuntu3.1+esm1       (Changelog nicht verfügbar)
      docker-ce   5:28.0.4-1~ubuntu.24.04~noble → 5:28.1.1-1~ubuntu.24.04~noble
      tzdata      2025a-0ubuntu0.24.04 → 2025b-0ubuntu0.24.04.1
   Offene Lücken ohne Fix:
      Paket    installiert               CVE                   Status
 KEV  libxml2  2.9.14+dfsg-1.3ubuntu3.1  CVE-2025-7000 (high)  kein Fix

━━ pdf-ansible — FEHLER: ssh timeout nach 120s ━━

Zusammenfassung: 2 Hosts, 5 Updates, 3 Security, 2 KEV-Fix verfügbar, 1 offene Lücke (1 KEV), 1 Host nicht erreichbar
```

`SEC` = Security-Update, `KEV` = Lücke auf der CISA-KEV-Liste. In der Übersicht heißt
`KEV-Fix`: so viele Updates beheben eine KEV-Lücke. `nicht geprüft` heißt: Die Lücken-Prüfung
war für den Host nicht möglich (Grund steht im Host-Block).

### HTML-Report

`--html PFAD` schreibt denselben Report zusätzlich als HTML-Datei. Die Terminal-Ausgabe
bleibt unverändert. `--security-only`, `--details` und `--kev-recent` wirken auch auf die
Datei.

- Eine einzige Datei: CSS ist eingebettet, kein JavaScript, keine externen Ressourcen.
  Sie kann also gemailt oder archiviert werden
- Übersichtstabelle mit Links zu den Host-Abschnitten, Hosts mit Handlungsbedarf
  (Security, KEV, Fehler) sind rot markiert
- Mit `--details` stehen Changelog und CVE-Beschreibungen in aufklappbaren Blöcken.
  Beim Drucken (bzw. „Als PDF speichern“ im Browser) sind sie automatisch aufgeklappt
- Hell/Dunkel folgt der Systemeinstellung

Kann die Datei nicht geschrieben werden, gibt es eine Fehlermeldung, und der Exit-Code
ist 2. Die Terminal-Ausgabe erscheint trotzdem.

## Betrieb ohne sudo

Das Skript braucht sudo nur für das `apt-get update` vor der Prüfung. Mit `--no-refresh`
läuft es mit einem normalen User ohne sudo-Rechte. Ausgewertet werden dann die
Paketlisten, die auf dem Host schon vorhanden sind. Ubuntu aktualisiert sie per
`apt-daily.timer` normalerweise einmal am Tag.

Weil die Infos dann veraltet sein können, steht bei jedem Host eine Warnung mit dem Stand:

```
━━ webserver (Ubuntu 24.04) — 3 Updates, 1 Security ━━
  ⚠ Paketlisten nicht aktualisiert (--no-refresh), Stand 2026-11-12 06:12 (vor 2 Tagen) – Updates und Security-Infos können veraltet sein
```

Schlägt das Update ohne `--no-refresh` fehl (z. B. sudo verlangt ein Passwort), läuft der
Report ebenfalls weiter, mit der Fehlermeldung und demselben Stand.

Den Stand ermittelt das Skript aus dem neuesten dieser Zeitstempel auf dem Host:

1. `/var/lib/apt/periodic/update-success-stamp` bzw. `update-stamp`
   (von update-notifier bzw. `apt-daily`)
2. Änderungszeit von `/var/lib/apt/lists/partial` (ändert apt bei jedem Update)
3. neueste `*Release`-Datei in `/var/lib/apt/lists` (nur das Veröffentlichungsdatum des
   Repos, daher ein grober Notbehelf)

Findet es keinen davon, heißt es „Stand unbekannt“. Das Alter wird mit der Uhr des Hosts
berechnet, eine abweichende lokale Uhr spielt also keine Rolle.

Achtung beim Exit-Code: Bei alten Paketlisten kann er `0` sein, obwohl längst
Security-Updates bereitstehen.

## Exit-Codes

Damit lässt sich der Report in Cron oder Monitoring einbinden:

| Code | Bedeutung |
|---|---|
| `0` | nichts Dringendes: keine Security-Updates, keine offene KEV-Lücke |
| `1` | Security-Updates stehen an **oder** eine offene KEV-Lücke ohne Fix existiert |
| `2` | mindestens ein Host nicht erreichbar, oder Aufruf-/Inventory-Fehler |
| `3` | Prüfung unvollständig: KEV-Liste oder Ubuntu-Schwachstellendaten nicht abrufbar bzw. Host-Daten fehlen |

Bei mehreren zutreffenden Codes gilt die Reihenfolge 2 vor 3 vor 1.

Für Cron mit Mailversand gibt es einen fertigen Wrapper, siehe
[Lokal per Cronjob](#lokal-per-cronjob).

## Lokal per Cronjob

Mit `--local` prüft das Skript den Rechner, auf dem es läuft. Das Remote-Skript wird
dann per `bash` statt per `ssh` ausgeführt, Inventory und SSH-Config entfallen. Der Host
heißt im Report wie `hostname`. Voraussetzung auf dem Server ist zusätzlich Python ≥ 3.9
(bei Ubuntu vorinstalliert).

```bash
sudo ./aptfleet.py --local                 # als root: apt-get update ohne sudo
./aptfleet.py --local --no-refresh         # als normaler User
```

Läuft das Skript als root, ruft es `apt-get update` direkt auf, sonst per `sudo -n`.

### Wrapper mit Mailversand

`cron/aptfleet-mail.sh` ruft `aptfleet.py` auf und verschickt das Ergebnis als
Mail: Textreport als Mailtext, HTML-Report als HTML-Ansicht der Mail und zusätzlich als
Anhang. Der Betreff nennt Host und Ergebnis, z. B.
`[updates] rootserver: Security-Updates oder offene KEV-Lücke`.

Die Konfiguration steht in einer env-Datei (Vorlage: `cron/mail.env.sample`):

| Variable | Wirkung | Default |
|---|---|---|
| `APTFLEET_ARGS` | Optionen für `aptfleet.py` (`--no-progress`, `--html` setzt der Wrapper) | `--local --details` |
| `MAIL_TO` | Empfänger, mehrere mit Komma | – (Pflicht) |
| `MAIL_FROM` | Absender | `aptfleet@<hostname -f>` |
| `MAIL_WHEN` | `problems`: nur bei Exit-Code ≠ 0, `always`: bei jedem Lauf | `problems` |
| `MAIL_TRANSPORT` | `sendmail` (lokaler MTA), `smtp` (direkt per `curl`), `print` (nur ausgeben) | `sendmail` |
| `MAIL_HTML_INLINE` | `1`: HTML als Mailinhalt, `0`: nur als Anhang | `1` |
| `MAIL_SUBJECT_PREFIX` | Präfix im Betreff | `[updates]` |
| `SENDMAIL` | sendmail-Binary | `/usr/sbin/sendmail` |
| `SMTP_URL` | z. B. `smtps://mail.example.com:465` oder `smtp://mail.example.com:587` | – |
| `SMTP_STARTTLS` | `1`: STARTTLS erzwingen (für Port 587) | `0` |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP-Login (wird nicht auf der Kommandozeile übergeben) | – |
| `REPORT_NAME` | Hostname in Betreff und Dateiname | `hostname` |
| `REPORT_DIR` | HTML-Reports zusätzlich hier archivieren | – |
| `REPORT_KEEP_DAYS` | ältere Reports in `REPORT_DIR` löschen | `30` |
| `APTFLEET`, `PYTHON` | Pfad zu `aptfleet.py` bzw. Interpreter | `../aptfleet.py`, `python3` |

`MAIL_TRANSPORT=smtp` braucht `curl`, aber keinen MTA auf dem Server. Der Wrapper geht
auch ohne `--local`, also für den zentralen Betrieb per SSH (`APTFLEET_ARGS` mit
`--inventory` …).

Exit-Code des Wrappers: der von `aptfleet.py`, `4` wenn der Mailversand scheitert,
`5` bei Konfigurationsfehlern. Fehlermeldungen gehen auf stderr, also per cron-Mail an
`MAILTO`.

### Einrichtung

Mit dem [.deb-Paket](#als-deb-paket) liegen Wrapper, env-Datei und Cronjob schon an Ort
und Stelle:

```bash
sudoedit /etc/aptfleet/mail.env                 # MAIL_TO, Versandweg …
sudo aptfleet-mail --dry-run | less             # Testlauf, verschickt nichts
sudoedit /etc/cron.d/aptfleet              # Cron-Zeile einkommentieren
```

Ohne Paket:

```bash
sudo cp -r updates_report /opt/
sudo cp /opt/aptfleet/cron/mail.env.sample /etc/aptfleet/mail.env
sudo chmod 600 /etc/aptfleet/mail.env
sudoedit /etc/aptfleet/mail.env                 # MAIL_TO, Versandweg …

# Testlauf: Mail immer erzeugen und nur ausgeben statt verschicken
sudo /opt/aptfleet/cron/aptfleet-mail.sh --dry-run /etc/aptfleet/mail.env | less

sudo cp /opt/aptfleet/cron/aptfleet.cron /etc/cron.d/aptfleet
```

`cron/aptfleet.cron` startet den Wrapper täglich um 06:30 als root. Aufruf:
`aptfleet-mail.sh [--dry-run] [ENV-DATEI]`, ohne Angabe gilt `/etc/aptfleet/mail.env`.

## Datenquellen und Cache

| Quelle | Wofür | Cache | gültig |
|---|---|---|---|
| `ubuntu.com/security/cves/<id>.json` | Priorität/Beschreibung einzelner CVEs | `~/.cache/aptfleet/cves.json` | 7 Tage |
| CISA KEV-Feed (JSON) | aktiv ausgenutzte CVEs | `~/.cache/aptfleet/kev.json` | 24 h |
| Ubuntu-OVAL (`security-metadata.canonical.com`) | offene Lücken je Release | `~/.cache/aptfleet/oval-<codename>.json` | 24 h |

Ist eine Quelle nicht erreichbar, wird ein vorhandener älterer Cache genutzt. Der Report
gibt dann einen Hinweis mit dem Datenstand aus. Ohne jeden Cache fehlt der jeweilige
Teil, und der Exit-Code ist 3. Cache leeren: `rm -rf ~/.cache/aptfleet`.

## Tests

Die Tests laufen ohne echte Hosts und ohne Netz:

```bash
cd updates_report
python3 -m unittest discover -s tests -t .
```

## Aufbau

| Modul | Aufgabe |
|---|---|
| `aptfleet.py` | CLI, Inventory, Ablaufsteuerung, Exit-Code |
| `remote.py` | SSH- bzw. lokaler Aufruf und Remote-Skript (Abschnitte `===SECTION …===`) |
| `progress.py` | Fortschrittsanzeige auf stderr (nur im Terminal) |
| `parsing.py` | Remote-Ausgabe in `HostReport`s zerlegen |
| `debversion.py` | Vergleich von Debian-Versionsnummern |
| `cve_info.py` | Ubuntu-CVE-API mit Cache |
| `kev.py` | CISA-KEV-Katalog mit Cache |
| `oval.py` | Ubuntu-OVAL-Feed laden und parsen |
| `vulns.py` | offene Lücken aus installierten Paketen und OVAL ermitteln |
| `render.py` | Textausgabe und gemeinsame Aufbereitung (Sortierung, Übersicht, Zusammenfassung) |
| `render_html.py` | HTML-Report (`--html`) |
| `cron/aptfleet-mail.sh` | Cron-Wrapper: Report erzeugen und per Mail verschicken |
| `packaging/`, `Makefile` | .deb-Paket (nfpm-Konfiguration, Shims, Cronjob, Maintainer-Skripte) |
