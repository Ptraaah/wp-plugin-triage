# wp-plugin-triage

A static triage scanner for WordPress plugins. Point it at a wordpress.org slug or a local plugin directory and it maps every `wp_ajax` / `wp_ajax_nopriv` handler and REST route to its callback body, then scores how close dangerous sinks (option writes, user creation, file upload, raw SQL, unserialize, eval) sit to unprivileged input, and whether a guard appears near them.

Born from real bug bounty work: this is the exact first-pass tool used to sweep roughly 1,500 WordPress plugins across every install band while hunting for Patchstack-eligible vulnerabilities.

## Usage

```bash
python3 wp_triage.py <plugin-slug>          # downloads from wordpress.org
python3 wp_triage.py --dir ./my-plugin      # scans a local directory
python3 wp_triage.py <slug> --json out.json # machine readable results
```

No dependencies beyond Python 3's standard library.

## Reading the output

```
  95 ajax_nopriv  wrcpt_update_package_features   UNGUARDED? update_option,delete_option
```

High score plus `UNGUARDED?` means: read this callback first. It does **not** mean vulnerable. The honest lesson from 1,500 plugins of audits:

- Most top hits are false positives. The guard is real but lives in a custom helper function (`check_permissions()`, a token verifier, a capability wrapper) that no regex can follow. Open the helper before concluding anything.
- Famous, actively maintained plugins are almost always hardened, often with comments naming the CVE that closed the hole you just found.
- A scanner hit is a reading assignment, not a report. Never submit anything you have not reproduced against a real install.

## What it deliberately does not do

- No dynamic testing, no requests to any live site, no exploitation. It reads code.
- No verdicts. Severity, reachability, and impact are your job.

## Indonesian summary

Alat sortir awal untuk audit keamanan plugin WordPress. Memetakan handler AJAX dan rute REST ke isi fungsinya, lalu memberi skor kedekatan fungsi berbahaya dengan masukan dari pengguna tak berhak. Hasilnya adalah daftar bacaan prioritas, bukan vonis kerentanan. Selalu baca kode penjaganya dengan tangan sebelum percaya.

## License

MIT.

Created by ptraaa, from the AMERTA / Patchstack audit workflow.

## Support

If this project helped you, you can support its development on Trakteer: https://trakteer.id/adel_putra2

Kalau proyek ini membantu Anda, Anda bisa mendukung pengembangannya lewat Trakteer: https://trakteer.id/adel_putra2
