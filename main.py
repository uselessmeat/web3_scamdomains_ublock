import hashlib
import requests
import os


def scamsniffer_to_ublock():
    url = 'https://raw.githubusercontent.com/scamsniffer/scam-database/refs/heads/main/blacklist/domains.json'
    current_domains_raw = 'scamsniffer_domains_raw.txt'
    current_domains = 'scamsniffer_domains.txt'

    if not os.path.exists(current_domains_raw):
        open(current_domains_raw, 'w').close()

    if not os.path.exists(current_domains):
        open(current_domains, 'w').close()

    response = requests.get(url)
    new_hash = hashlib.sha256(response.content).hexdigest()

    with open(current_domains_raw, 'rb', buffering=0) as f:
        old_hash = hashlib.file_digest(f, 'sha256').hexdigest()

    if new_hash == old_hash:
        return

    with open(current_domains_raw, 'wb') as f:
        f.write(response.content)

    domains = response.json()

    with open(current_domains, 'w') as f:
        for domain in domains:
            f.write(f'||{domain.strip()}^\n')


if __name__ == '__main__':
    scamsniffer_to_ublock()
