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
  Ohne sudo-Rechte mit `--no-refresh` aufrufen (siehe [Betrieb ohne sudo](#betrieb-ohne-sudo))

## Installation

Das Verzeichnis `updates_report/` irgendwohin kopieren und fertig:

```bash
cp -r updates_report ~/tools/
~/tools/updates_report/check_updates.py --help
```

## Hosts festlegen

Es gibt drei Wege.

### 1. Ad hoc: `--host` + `--user`

Hosts direkt angeben. Es gilt die normale `~/.ssh/config` (Aliase, Keys, `ProxyJump`),
außer es wird `--ssh-config` angegeben:

```bash
./check_updates.py --user admin --host web1.example.com --host 10.0.0.12
./check_updates.py --user ansiadm --host mein-alias-aus-ssh-config
```

### 2. Eigenes Inventory: `--inventory` / `--ssh-config`

Inventory und SSH-Config können irgendwo liegen:

```bash
./check_updates.py --inventory ~/etc/hosts.ini --ssh-config ~/etc/ssh_hosts.conf
./check_updates.py --inventory ~/etc/hosts.ini     # SSH über ~/.ssh/config
```

Ohne `--ssh-config` wird die Default-Datei (siehe 3.) genutzt, falls sie existiert,
sonst die normale `~/.ssh/config`. Wie beide Dateien aussehen, steht unter
[Inventory-Format](#inventory-format) und [SSH-Config](#ssh-config).

### 3. Defaults im Elternverzeichnis

Ohne `--user` und `--inventory` liest das Skript zwei Dateien aus dem Verzeichnis
**über** `updates_report/`:

```
<projekt>/
├── virtualhosts                          # Inventory
├── ssh_config_rootserver_ansible.conf    # SSH-Config, wird per ssh -F genutzt
└── updates_report/
    └── check_updates.py
```

Dann prüft ein Aufruf alle Hosts:

```bash
./check_updates.py
./check_updates.py --host host-b      # nur einer (muss im Inventory stehen)
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
./check_updates.py [Optionen]
```

| Option | Wirkung |
|---|---|
| `--host NAME` | nur diesen Host prüfen, mehrfach möglich. Ohne `--user` muss der Name im Inventory stehen |
| `--user NAME` | SSH-User. Nutzt die `--host`-Angaben direkt, ohne Inventory |
| `--inventory PFAD` | Inventory-Datei (Default: `../virtualhosts`) |
| `--ssh-config PFAD` | SSH-Config für `ssh -F` (Default: `../ssh_config_rootserver_ansible.conf`, falls vorhanden, sonst `~/.ssh/config`) |
| `--security-only` | nur Security-Updates anzeigen |
| `--details` | neue Changelog-Einträge der Updates anzeigen. Holt auch CVE-Infos für offene Lücken |
| `--package NAME` | nur dieses Binärpaket, mehrfach möglich |
| `--no-refresh` | kein `apt-get update` vorher, braucht dann kein sudo. Zeigt pro Host, wie alt die Paketlisten sind |
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
