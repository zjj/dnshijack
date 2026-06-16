CSV -> dnshijack TOML config

This folder contains a simple script to convert a CSV of popular domains into a `dnshijack` TOML config (`[[records]]` entries).

Usage examples:

Generate top 1000 A records with TTL 300:

```bash
python3 scripts/csv_to_toml.py -i pdns_20260523_top10w.csv -o ../config/generated.toml --top 1000 --ttl 300
```

If the CSV contains a `parse_cnt` column you can use the `--top` or `--min-count` flags to filter by popularity.

Default column names are `domain_name,a_record_ip,parse_cnt`. Use `--domain-col` and `--ip-col` to change.
