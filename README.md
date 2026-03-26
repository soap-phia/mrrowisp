![night chan](./night%20chan.png)

> [!WARNING]
> mraow

Lightweight Wisp v1/v2 + Twisp server. Configure via `config.json` or with CLI flags able to override individual fields.


Place a JSON file (default `config.json` in the working directory). Example: see `example.config.json`.

Fields (all optional; CLI flags override):

| Flag | Short |  Type  | Description | Default |
|------|-------|--------|-------------|---------|
| `(--)host` |  `-h`   |string | Bind address for WebSocket listener | `0.0.0.0` |
| `(--)port` |  `-p`   |number | Port for WebSocket listener | `6001` |
| `(--)root` |  `-r`   |string | Root directory for folders to expose to Twisp | `./twisp` |
| `(--)buffer_bytes` | `-b` | number | Flow Control window for client-to-backend and CONTINUE (in bytes). | `16777216` |
| `(--)continue_threshold_bytes` | `-t` | number | Time in between sent CONTINUE's | `15099494` |

- `host` (string): Bind address for the WebSocket listener. Default `0.0.0.0`.
- `port` (number): WebSocket port. Default `6001`.
- `root` (string): Root directory containing per-server folders used by Twisp. Default `./servers`.
- `buffer_bytes` (number): Flow-control window (bytes) for client → backend and initial CONTINUE. Default `16 * 1024 * 1024` (16 MiB).
- `continue_threshold_bytes` (number): When sent bytes since last CONTINUE reach this value, another CONTINUE is sent. Default is 90% of `buffer_bytes`.

You can omit `--config` if using the default `config.json`. Any CLI flag can override a single field without changing the file.

