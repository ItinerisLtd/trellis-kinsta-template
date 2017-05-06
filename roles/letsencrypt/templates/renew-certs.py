#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import time

from hashlib import sha1
from subprocess import CalledProcessError, check_output, STDOUT

failed = False
letsencrypt_cert_ids = {{ letsencrypt_cert_ids }}

for site in {{ sites_using_letsencrypt }}:
    csr_path = os.path.join('{{ acme_tiny_data_directory }}', 'csrs', '{}-{}.csr'.format(site, letsencrypt_cert_ids[site]))
    cert_path = os.path.join('{{ letsencrypt_certs_dir }}', '{}-{}.cert'.format(site, letsencrypt_cert_ids[site]))
    bundled_cert_path = os.path.join('{{ letsencrypt_certs_dir }}', '{}-bundled.cert'.format(site))

    # Generate or update root cert if needed
    if not os.access(csr_path, os.F_OK):
        failed = True
        print('The required CSR file {} does not exist. This could happen if you changed site_hosts and have '
              'not yet rerun the letsencrypt role. Create the CSR file by running the Trellis server.yml playbook with '
              '`--tags letsencrypt`'.format(csr_path), file=sys.stderr)
        continue

    elif os.access(cert_path, os.F_OK) and time.time() - os.stat(cert_path).st_mtime < {{ letsencrypt_min_renewal_age }} * 86400:
        print('Certificate file {} already exists and is younger than {{ letsencrypt_min_renewal_age }} days. '
              'Not creating a new certificate.'.format(cert_path))

    else:
        cmd = ('/usr/bin/env python {{ acme_tiny_software_directory }}/acme_tiny.py '
            '--quiet '
            '--ca {{ letsencrypt_ca }} '
            '--account-key {{ letsencrypt_account_key }} '
            '--csr {} '
            '--acme-dir {{ acme_tiny_challenges_directory }}'
            ).format(csr_path)

        try:
            cert = check_output(cmd, stderr=STDOUT, shell=True)
        except CalledProcessError as e:
            failed = True
            print('Error while generating certificate for {}\n{}'.format(site, e.output), file=sys.stderr)
            continue
        else:
            with open(cert_path, 'w') as cert_file:
                cert_file.write(cert)

            print('Created certificate {}'.format(cert_file))

    # Ensure intermediate cert is available for creating bundled cert
    if not os.access('{{ letsencrypt_intermediate_cert_path }}', os.F_OK):
        failed = True
        print('The required intermediate cert file {{ letsencrypt_intermediate_cert_path }} does not exist. '
              'This could happen if you have not yet run the letsencrypt role with the latest `letsencrypt_intermediate_cert_path` value. '
              'Try running the Trellis server.yml playbook with `--tags letsencrypt`', file=sys.stderr)
        continue

    # Retrieve binary content for root cert, intermediate cert, and bundled cert
    with open(cert_path, 'rb') as cert_file:
        cert = cert_file.read()

    with open('{{ letsencrypt_intermediate_cert_path }}', 'rb') as intermediate_cert_file:
        intermediate_cert = intermediate_cert_file.read()

    new_bundled_needed = True
    if os.access(bundled_cert_path, os.F_OK):
        with open(bundled_cert_path, 'rb') as bundled_cert_file:
            bundled_cert = bundled_cert_file.read()

        # Compare sha1 hashes of new vs. existing bundled content
        new = sha1()
        new.update(cert + intermediate_cert)
        existing = sha1()
        existing.update(bundled_cert)
        new_bundled_needed = new.hexdigest() != existing.hexdigest()

    # Generate or update bundled cert if needed
    if new_bundled_needed:
        with open(bundled_cert_path, 'wb') as bundled_cert_file:
            bundled_cert_file.write(cert + intermediate_cert)

        print('Created bundled certificate {}'.format(bundled_cert_path))

if failed:
    sys.exit(1)
