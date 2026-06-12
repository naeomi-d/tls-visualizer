# TLS Handshake Visualizer

A Python-based cybersecurity tool that analyzes and visualizes 
the TLS 1.3 handshake process of any HTTPS website.

## What it does
- Visualizes all 5 steps of the TLS handshake
- Displays certificate details (issuer, validity, expiry)
- Shows cipher suite and key exchange algorithm
- Gives a security rating out of 100
- Compares TLS security across multiple websites

## Real findings
| Website | Score | Cipher |
|---------|-------|--------|
| google.com | 100/100 | AES-256-GCM |
| flipkart.com | 100/100 | AES-256-GCM |
| github.com | 90/100 | AES-128-GCM |
| sbi.co.in | 80/100 | AES-128-GCM |

## Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography rich
```

## Usage
```bash
python tls_visualizer.py
```

## Technologies
- Python 3
- ssl — TLS handshake analysis
- cryptography — X.509 certificate parsing
- rich — terminal visualization

## Relevance to 6G Security
TLS 1.3 is the current standard for securing internet 
communications. As 6G networks are developed, understanding 
TLS handshake vulnerabilities and cipher suite weaknesses 
is critical for next-generation security standards (3GPP).
