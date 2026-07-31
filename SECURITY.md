# Security policy

ControlForge is an educational security-engineering project and is not an endpoint protection product.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email `chanikya1@icloud.com` with:

- affected version and component;
- reproducible steps or proof of concept;
- expected impact;
- any suggested remediation.

Please allow 90 days for coordinated remediation before public disclosure.

## Supported versions

Only the most recent tagged release receives security fixes.

## Secret handling

The repository must contain synthetic fixtures only. Vendor credentials belong in a managed secret store and must be injected at runtime. Pull requests are scanned for accidental credentials before release.
