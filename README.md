# reaparr

Watches Transmission via its RPC API for single-file torrents of unwanted file types that **Sonarr or Radarr grabbed**, blocklists the release there (so they search for a replacement), then removes the torrent.

Anything not in Sonarr's or Radarr's queue is never touched, so torrents you add yourself are safe.

## Requirements

- Transmission > Settings > Remote > enable remote access (note the port).
- Sonarr and/or Radarr using that Transmission as a download client.

## Usage

```
./reaparr.py --sonarr-url http://localhost:8989 --radarr-url http://localhost:7878 --dry-run   # report only
./reaparr.py --sonarr-url http://localhost:8989 --radarr-url http://localhost:7878             # really delete
```

| Option                       | Default                                           | Notes                                              |
|------------------------------|---------------------------------------------------|----------------------------------------------------|
| `--sonarr-url`, `--radarr-url` | none                                            | at least one required; see Sonarr / Radarr         |
| `--port`, `--host`           | 9091, localhost                                   | `--url` overrides both                             |
| `--dangerous-ext`            | `bat cmd exe iso lnk ps1 scr sh vbs`              | executables, scripts, shortcuts, disk images; alias: `--ext` |
| `--archive-ext`              | `7z arj lzh rar zip zipx`                         | same rules as `--dangerous-ext`                    |
| `--interval`                 | 10                                                | seconds between checks                             |
| `--keep-data`                | off                                               | remove torrent, keep files                         |
| `--dry-run`                  | off                                               | no removals                                        |
| `--once`                     | off                                               | single check, then exit                            |
| `--user`, `--password`       | none                                              | see Auth                                           |

## What gets removed

A torrent is removed only if all of these hold:

- it is a single file (multi-file torrents are never touched);
- that file has a `--dangerous-ext` or `--archive-ext` extension. The two lists are treated the same and kept apart only so each can be changed on its own. An extension in both is listed once. Give either option with no values to empty it;
- its hash is in Sonarr's or Radarr's queue.

Matching torrents that aren't in either queue are logged once as `SKIPPING` and checked again every sweep. Sonarr and Radarr poll the download client periodically, so a fresh grab can take a short while to show up in their queue. It's removed once it does.

## Auth

Password lookup order: `--password`, macOS Keychain, interactive prompt (also prompts on a 401 if no credentials given). Wrong credentials exit with an error.

```
security add-generic-password -a USERNAME -s reaparr -w
```

## Sonarr / Radarr

`--sonarr-url http://localhost:8989` and/or `--radarr-url http://localhost:7878`. For each matching torrent (matched by hash), reaparr removes the item from that app's queue with **blocklist** on (via `DELETE /api/v3/queue/{id}`, which both apps share). The app then searches for a replacement, and reaparr removes the torrent from Transmission itself, so `--keep-data` works.

API keys (Settings > General in each app): `--sonarr-api-key` / `--radarr-api-key`, else Keychain, else prompt.

```
security add-generic-password -a sonarr -s reaparr -w
security add-generic-password -a radarr -s reaparr -w
```

## launchd

Expects settings to live in `reaparr.conf` (see `reaparr.conf.example`). No terminal under launchd, so passwords/API keys must be in Keychain (above).

```
# start launch agent 
# first run creates reaparr.conf to edit; then run again to generate the plist from template + conf, install, (re)load
make install    
              
# stop and remove the launch agent  
make uninstall

# view logs
tail -f ~/Library/Logs/io.github.stephan5.reaparr.log
```

Run `make install` after changing `reaparr.conf` or `reaparr.py`. Add `--dry-run` to the conf to test first.

## Notes

- Magnet links are only checked once metadata arrives, so they may be partly downloaded before removal.
- Auth failure exits; launchd `KeepAlive` will keep restarting it.

## Tests

Stdlib `unittest`, no network, Transmission or Sonarr needed:

```
make test
```
