# AIT Isolation Protocol V3

AIT is a target domain. The P1 release must be created before any AIT target data is mounted or read.

Allowed before P1 scoring:

- Read public format documentation.
- Implement generic parsers.
- Run frozen source-domain checkpoints on sealed target records.
- Save prediction records without labels.

Forbidden before predictions are sealed:

- Reading AIT attack labels, rule groups, MITRE fields, or attack phases.
- Training any module on AIT records.
- Selecting thresholds or epochs from AIT behavior.
- Adding target-specific IPs, account names, filenames, or rule IDs to dictionaries.
- Reworking source training after looking at target metrics.

Required order:

1. Lock code, configuration, checkpoints, and hashes.
2. Create a release manifest.
3. Run target inference without labels.
4. Hash and mark predictions sealed.
5. Load target labels only for scoring.
6. Keep P1, P2, and P3 reports separate.
