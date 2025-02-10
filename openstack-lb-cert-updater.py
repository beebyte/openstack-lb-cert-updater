#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "python-barbicanclient",
#     "python-octaviaclient",
#     "python-openstackclient",
# ]
# ///

# OpenStack Load Balancer Cert Updater
# This script can be used to keep OpenStack load balancers up to date with 
# Letsencrypt certificates.

# INSTALLATION:
# Requires uv to run: https://github.com/astral-sh/uv
# Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh

# Relevant docs:
# https://docs.openstack.org/openstacksdk/latest/user/index.html
# https://docs.openstack.org/octavia/latest/user/guides/basic-cookbook.html
# https://docs.openstack.org/api-guide/key-manager/containers.html


import os
import time
import sys
import pprint  # noqa
from openstack import connection
import openstack
import argparse


def make_connection():
    """Create an OpenStack connection object

    This requires having source an openrc.sh file first.
    """
    conn = connection.Connection(
        auth_url=os.environ['OS_AUTH_URL'],
        project_name=os.environ['OS_PROJECT_NAME'],
        auth_type=os.environ['OS_AUTH_TYPE'],
        username=os.environ['OS_USERNAME'],
        password=os.environ['OS_PASSWORD'],
        domain_name=os.environ['OS_DOMAIN_NAME'],
    )
    return conn

### Commands, these are the functions that are called by the argparse subparsers

def cmd_list_load_balancers(args, conn):
    """List all OpenStack load balancers available to the user"""
    lbs = conn.load_balancer.load_balancers()
    for lb in lbs:
        print('Name: %s' % lb.name)
        print('Description: %s' % lb.description)
        print('ID: %s' % lb.id)
        for lb_listener in lb.listeners:
            listener = conn.load_balancer.get_listener(lb_listener['id'])
            print('Listener: %s\n  %s %s\n  tls_container_ref: %s\n  sni_container_refs: %s' % (listener.id, listener.protocol, listener.protocol_port, listener.default_tls_container_ref, listener.sni_container_refs))
            print()
        print()


def cmd_list_secrets(args, conn):
    """List all OpenStack secrets available to the user"""
    for secret in conn.key_manager.secrets():
        print('Name: %s' % secret.name)
        print('Status: %s' % secret.status)
        print('Type: %s' % secret.secret_type)
        print('ID: %s' % secret.id.split('/')[-1])
        print('Ref: %s' % secret.secret_ref)
        print()


def cmd_list_containers(args, conn):
    """List all OpenStack secret containers available to the user"""
    for container in conn.key_manager.containers():
        # print(container)
        print('Name: %s' % container.name)
        print('Status: %s' % container.status)
        print('Type: %s' % container.type)
        print('ID: %s' % container.id.split('/')[-1])
        for secret in container.secret_refs:
            print('Secret: %s %s' % (secret['name'], secret['secret_ref']))
        print()


def cmd_delete_secret(args, conn):
    """Delete the secret with the given ID"""
    conn.key_manager.delete_secret(args.secret)
    print('Deleted secret %s' % args.secret)


def cmd_delete_container(args, conn):
    """Delete the container with the given ID"""
    delete_container(conn, args.container, args.include_secrets)


class CertificateBundleManager:
    """Stores a collection of CertificateBundle objects."""
    def __init__(self, conn, name=None):
        self.conn = conn
        self.name = name
        self.bundles = []

    def __eq__(self, other):
        for a_bundle in self.bundles:
            match = False
            for b_bundle in other.bundles:
                if a_bundle == b_bundle:
                    match = True
                    break
            if not match:
                return False
        for a_bundle in other.bundles:
            match = False
            for b_bundle in self.bundles:
                if a_bundle == b_bundle:
                    match = True
                    break
            if not match:
                return False
        return True

    def print_info(self):
        print('CertificateBundleManager "%s" data' % (self.name or ''))
        for bundle in self.bundles:
            print('Bundle: %s' % (bundle))
        print()

    def add_bundle(self, cert_data, key_data, chain_data):
        self.bundles.append(CertificateBundle(self.conn, cert_data, key_data, chain_data))

    def add_bundle_from_files(self, cert_file, key_file, chain_file):
        if not os.path.isfile(cert_file):
            print('Certificate file not found: %s' % cert_file)
            raise FileNotFoundError
        if not os.path.isfile(key_file):
            print('Key file not found: %s' % key_file)
            raise FileNotFoundError
        if chain_file and not os.path.isfile(chain_file):
            print('Chain file not found: %s' % chain_file)
            raise FileNotFoundError
        cert_data = open(cert_file, 'r').read()
        key_data = open(key_file, 'r').read()
        chain_data = None
        if chain_file:
            chain_data = open(chain_file, 'r').read()
        bundle = CertificateBundle(self.conn, cert_data, key_data, chain_data)
        self.bundles.append(bundle)

    def add_bundle_from_container(self, container_id):
        container = self.conn.key_manager.get_container(container_id)
        cert_data = None
        key_data = None
        chain_data = None
        for secret_ref in container.secret_refs:
            cert_secret = self.conn.key_manager.get_secret(secret_ref['secret_ref'].split('/')[-1])
            if secret_ref['name'] == 'certificate':
                cert_data = cert_secret.payload
            elif secret_ref['name'] == 'private_key':
                key_data = cert_secret.payload
            elif secret_ref['name'] == 'intermediates':
                chain_data = cert_secret.payload
        bundle = CertificateBundle(self.conn, cert_data, key_data, chain_data, container_id)
        self.bundles.append(bundle)
        return True


class CertificateBundle:
    """Stores a collection if certificate, key and chain data

    This basically matches a OpenStack container with a certificate, key and chain.
    """
    def __init__(self, conn, cert_data, key_data, chain_data, container_id=None):
        self.conn = conn
        self.cert_data = cert_data.strip()
        self.key_data = key_data.strip()
        self.chain_data = chain_data
        if self.chain_data:
            self.chain_data = self.chain_data.strip()
        self.container_id = container_id

    def __eq__(self, other):
        if self.cert_data == other.cert_data and self.key_data == other.key_data and self.chain_data == other.chain_data:
            return True
        return False

    def __str__(self):
        return 'CertificateBundle: cert:%s %s %s container_id:%s' % (
            self._data_info(self.cert_data),
            self._data_info(self.key_data),
            self._data_info(self.chain_data),
            self.container_id
        )

    def _data_info(self, data):
        if data:
            return len(data)
        return 0

    def create_container(self):
        now = str(int(time.time()))
        name = 'autolb-cert-%s' % now
        cert_id = create_secret(self.conn, self.cert_data, name)
        name = 'autolb-key-%s' % now
        key_id = create_secret(self.conn, self.key_data, name)
        chain_id = None
        if self.chain_data:
            name = 'autolb-chain-%s' % now
            chain_id = create_secret(self.conn, self.chain_data, name)
        name = 'autolb-container-%s' % now
        self.container_id = create_container(self.conn, name, cert_id, key_id, chain_id)
        return self.container_id


def get_cmdline_cert_bundles(cert_bundles, args):
    """Create CertificateBundle objects from command line arguments

    Checks both --cert/--key/--chain and --letsencrypt arguments.
    """
    if args.cert and args.key:
        cert_bundles.add_bundle_from_files(args.cert, args.key, args.chain)
    if args.letsencrypt:
        for dir in args.letsencrypt:
            cert_file = os.path.join(dir, 'cert.pem')
            key_file = os.path.join(dir, 'privkey.pem')
            chain_file = os.path.join(dir, 'chain.pem')
            cert_bundles.add_bundle_from_files(cert_file, key_file, chain_file)
    return cert_bundles


def cmd_set_lb_cert(args, conn):
    """Update a load balancer listener with a new certificate"""
    print('## Loading data')
    new_cert_bundles = CertificateBundleManager(conn, name='new')
    get_cmdline_cert_bundles(new_cert_bundles, args)
    conn.load_balancer.get_load_balancer(args.lb)
    listener = conn.load_balancer.get_listener(args.listener)
    old_cert_bundles = CertificateBundleManager(conn, name='old')
    old_cert_bundles.add_bundle_from_container(listener.default_tls_container_ref.split('/')[-1])
    if len(listener.sni_container_refs) > 10:
        print('Reading %d old certificates, this may take a while' % len(listener.sni_container_refs))
    for container_id in listener.sni_container_refs:
        old_cert_bundles.add_bundle_from_container(container_id.split('/')[-1])
    new_cert_bundles.print_info()
    old_cert_bundles.print_info()
    if new_cert_bundles == old_cert_bundles:
        print('Certificates have not changed, exiting')
        return
    else:
        print('Certificates have changed, updating')
    print()
    print('## Creating and setting new containers')
    for cert_bundle in new_cert_bundles.bundles:
        cert_bundle.create_container()
    print('Setting new containers for load balancer listener %s, this might take a while' % (args.listener))
    default_container_id = new_cert_bundles.bundles[0].container_id
    sni_container_ids = [cert_bundle.container_id for cert_bundle in new_cert_bundles.bundles]
    conn.load_balancer.update_listener(args.listener, default_tls_container_ref=default_container_id, sni_container_refs=sni_container_ids)
    print('Done')
    print()
    print('## Cleaning up')
    for cert_bundle in old_cert_bundles.bundles:
        print('Deleting old container %s' % cert_bundle.container_id)
        delete_container(conn, cert_bundle.container_id, True)
    print()
    print('## Done')

### Helper functions

def cert_has_changed(conn, container_id, cert_file, key_file, chain_file):
    """Check if the given certificate files are different from the ones in the container"""
    cert_file_data = open(cert_file, 'r').read().strip()
    key_file_data = open(key_file, 'r').read().strip()
    container = conn.key_manager.get_container(container_id)
    cert_match = False
    key_match = False
    if chain_file:
        chain_match = False
        chain_file_data = open(chain_file, 'r').read().strip()
    else:
        chain_match = True
    for secret in container.secret_refs:
        cert_secret = conn.key_manager.get_secret(secret['secret_ref'].split('/')[-1])
        if cert_file_data == cert_secret.payload:
            cert_match = True
        elif key_file_data == cert_secret.payload:
            key_match = True
        elif chain_file and chain_file_data == cert_secret.payload:
            chain_match = True
    if cert_match and key_match and chain_match:
        return False
    return True


def create_secret(conn, pem_file_data, name):
    """Create a new OpenStack secret."""
    secret = conn.key_manager.create_secret(
        name=name,
        secret_type='certificate',
        payload=pem_file_data,
        payload_content_type="text/plain",
    )
    print('Created secret: %s' % secret.secret_ref)
    return secret.secret_ref


def create_container(conn, name, cert_id, key_id, chain_id):
    """Create a new OpenStack secret container."""
    secret_refs=[
        {
            'name': 'certificate',
            'secret_ref': cert_id,
        },
        {
            'name': 'private_key',
            'secret_ref': key_id,
        },
    ]
    if chain_id:
        secret_refs.append({
            'name': 'intermediates',
            'secret_ref': chain_id,
        })
    container = conn.key_manager.create_container(
        name=name,
        type='certificate',
        secret_refs=secret_refs,
    )
    print('Created container: %s' % container.container_ref)
    return container.container_ref


def delete_container(conn, container_id, include_secrets):
    try:
        container = conn.key_manager.get_container(container_id)
    except openstack.exceptions.NotFoundException:
        print('Container not found')
        return False
    if include_secrets:
        for secret in container.secret_refs:
            conn.key_manager.delete_secret(secret['secret_ref'].split('/')[-1])
            print('Deleted secret %s' % secret['secret_ref'])
    conn.key_manager.delete_container(container_id)
    print('Deleted container %s' % container_id)



def main():
    if 'OS_AUTH_URL' not in os.environ:
        print('OS_AUTH_URL not set in environment, please source a openrc.sh file')
        print('openrc.sh files can be downloaded from portal.beebyte.se:')
        print('Public cloud -> [User] -> Download openrc.sh')
        sys.exit(1)
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''OpenStack Load Balancer Cert Updater

This script can be used to update certificates on OpenStack load balancers.
It's primary usecase is to be able to use Letsencrypt certificates with OpenStack load balancers.'''
    )
    subparsers = parser.add_subparsers(
        title="Commands",
    )
    cmd = subparsers.add_parser("list-load-balancers", help="List load balancers")
    cmd.set_defaults(func=cmd_list_load_balancers)
    cmd = subparsers.add_parser("list-secrets", help="List secrets")
    cmd.set_defaults(func=cmd_list_secrets)
    cmd = subparsers.add_parser("list-containers", help="List secret containers")
    cmd.set_defaults(func=cmd_list_containers)
    cmd = subparsers.add_parser("set-lb-cert", help="Set a new certificate on a load balancer")
    cmd.add_argument('--lb', help='Load balancer ID', required=True)
    cmd.add_argument('--listener', help='Listener ID', required=True)
    cmd.add_argument('--cert', help='Path to certificate PEM file (cert.pem)', required=False)
    cmd.add_argument('--key', help='Path to secret key PEM file (privkey.pem)', required=False)
    cmd.add_argument('--chain', help='Path to certificate chain PEM file (chain.pem)', required=False)
    cmd.add_argument('--letsencrypt', help='Path to Letsencrypt certificate directory (/etc/letsencrypt/live/[CERT-DIR]). Can be given multiple times for multiple certs/domains', required=False, action='append', type=str)
    cmd.set_defaults(func=cmd_set_lb_cert)
    cmd = subparsers.add_parser("delete-secret", help="Delete a secret")
    cmd.add_argument('--secret', help='Secret ID', required=True)
    cmd.set_defaults(func=cmd_delete_secret)
    cmd = subparsers.add_parser("delete-container", help="Delete a secret container")
    cmd.add_argument('--container', help='Container ID', required=True)
    cmd.add_argument('--include-secrets', help='Also delete attached secrets', required=False, action='store_true', default=True)
    cmd.set_defaults(func=cmd_delete_container)

    args = parser.parse_args() # noqa
    if not hasattr(args, "func"):
        parser.print_help()
    else:
        conn = make_connection()
        args.func(args, conn)


if __name__ == '__main__':
    main()
