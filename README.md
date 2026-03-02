# Quick Suspicious File Scanner (Python CLI)

A lightweight, signature based Python CLI script that scans server files to detect potentially malicious code such as web shells, obfuscated payloads, and dangerous function usage.

This is not a full antivirus solution. It is designed to quickly highlight suspicious files for manual review.

---

## What It Does

This script:

- Scans selected file extensions
- Reads only the head and tail of large files for faster processing
- Detects common web shell and obfuscation patterns
- Flags long Base64 encoded blobs
- Generates a structured JSON report

---

## File Types Scanned

By default:

- php
- phtml
- php5
- php7
- inc
- js
- html
- htm
- py
- sh
- pl
- asp
- aspx
- jsp

---

## Suspicious Patterns Checked

Examples include:

- `eval(`
- `assert(`
- `base64_decode(`
- `gzinflate(`
- `str_rot13(`
- `shell_exec(`
- `system(`
- `exec(`
- `passthru(`
- `proc_open(`
- `popen(`
- `fsockopen(`
- `curl_exec(`
- `preg_replace` with `/e` modifier
- `$_GET / $_POST / $_REQUEST / $_COOKIE`
- `php://input`
- `wget / curl`
- `powershell`
- `nc / netcat`
- Long Base64 blobs

Especially suspicious combinations:

- `base64_decode` + `eval`
- `gzinflate` + `base64_decode`
- Obfuscation combined with superglobals

---

## Requirements

- Python 3.10+ recommended (works on most Python 3 versions)
- CLI access
- Proper read permissions

---

## Installation

1. Save the script as `quick_scan.py`
2. Place it outside your web root (recommended)
3. Run it from the command line

---

## Usage

### Basic Scan

```bash
python3 quick_scan.py /var/www
````

### Excluding System Directories

```bash
python3 quick_scan.py /var/www --exclude /proc --exclude /sys --exclude /dev --exclude /var/lib/docker
```

### Save Report to File

```bash
python3 quick_scan.py /var/www --out report.json
```

---

## Available Options

| Option               | Description                                 |
| -------------------- | ------------------------------------------- |
| `--exclude PATH`     | Exclude a directory prefix (repeatable)     |
| `--max-bytes NUMBER` | Maximum bytes read per file (default 512KB) |
| `--max-size NUMBER`  | Maximum file size to scan (default 10MB)    |
| `--ext .EXT`         | Add extra extension to scan (repeatable)    |
| `--out FILE`         | Write output to JSON file                   |

---

## Performance Tuning

For large servers:

Reduce bytes read per file:

```bash
python3 quick_scan.py /var/www --max-bytes 262144
```

Skip larger files:

```bash
python3 quick_scan.py /var/www --max-size 5242880
```

---

## Report Format

Output is generated in JSON format:

```json
{
  "root": "/var/www",
  "scanned_files": 1234,
  "skipped_entries": 567,
  "findings": [
    {
      "path": "/var/www/suspicious.php",
      "size": 2048,
      "hits": ["php_eval", "php_base64_decode"]
    }
  ]
}
```

---

## Limitations

* Signature based detection only
* False positives are possible
* Encrypted or compressed payloads may not be detected
* Minified JavaScript may trigger alerts

---

## Security Notes

* Do not run this script via web browser
* Do not place it inside your web root
* Avoid running as root unless necessary
* Do not immediately delete flagged files without reviewing them

---

## Recommended Enhancements

For stronger security coverage, consider:

* Adding CMS-specific rules (WordPress, Laravel, etc.)
* Excluding framework storage/cache directories
* Integrating YARA rules
* Implementing SHA256 file integrity baselining
* Running alongside ClamAV
