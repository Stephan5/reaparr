# reaparr

Watches Transmission via its RPC API and removes torrents containing unwanted file types. 
It optionally also blocklists the releases in Sonarr, so they won't be downloaded again.

## Requirements

Transmission > Settings > Remote > enable remote access (note the port).

## Usage

```
./reaparr.py --dry-run     # report only
./reaparr.py               # really delete
```

| Option                 | Default                                           | Notes                                                        |
|------------------------|---------------------------------------------------|--------------------------------------------------------------|
| `--port`, `--host`     | 9091, localhost                                   | `--url` overrides both                                       |
| `--ext`                | `arj bat cmd exe iso lnk lzh ps1 scr sh vbs zipx` | removed only if the torrent is a single file of one of these |
| `--interval`           | 30                                                | seconds between checks                                       |
| `--keep-data`          | off                                               | remove torrent, keep files                                   |
| `--dry-run`            | off                                               | no removals                                                  |
| `--once`               | off                                               | single check, then exit                                      |
| `--user`, `--password` | none                                              | see Auth                                                     |

## Auth

Password lookup order: `--password`, macOS Keychain, interactive prompt (also prompts on a 401 if no credentials given). Wrong credentials exit with an error.

```
security add-generic-password -a USERNAME -s reaparr -w
```

## Sonarr

With `--sonarr-url http://localhost:8989`, a matching torrent that is in Sonarr's queue (matched by torrent hash) is first removed from the queue and **blocklisted** via the Sonarr API (Sonarr then searches for a replacement), then removed from Transmission. Torrents not in Sonarr's queue are just removed from Transmission.

API key (Sonarr > Settings > General): `--sonarr-api-key`, else Keychain, else prompt.

```
security add-generic-password -a sonarr -s reaparr -w
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

Stdlib `unittest`, no network or Transmission needed:

```
make test
```
