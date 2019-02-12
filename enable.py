#!/usr/bin/env python

from __future__ import print_function

import sys
import argparse
from os import environ
import time
import requests
import re
import getpass
import random


def sleep():
    x = random.uniform(1.0, 3.0)
    print('  Sleeping %.2f seconds' % x)
    time.sleep(x)


DEFAULT_SERVICE = 'ssh'

parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description='Enable Charite firewall access to an external host.')

parser.add_argument(
    '--username',
    help='The username. Taken from CHARITE_FIREWALL_USERNAME if not given.')

parser.add_argument(
    '--password',
    help='The password. Taken from CHARITE_FIREWALL_PASSWORD if not given.')

parser.add_argument(
    '--noStandard', action='store_true', default=False,
    help='If given, do not request standard rules.')

parser.add_argument(
    '--noSpecific', action='store_true', default=False,
    help=('If given, do not request specific firewall rules (specified using '
          '--service and --host).'))

for i in map(str, range(0, 10)):
    parser.add_argument(
        '--service' + i,
        default=environ.get('CHARITE_FIREWALL_SERVICE' + i),
        help='Service name ' + i)

    parser.add_argument(
        '--host' + i,
        default=environ.get('CHARITE_FIREWALL_HOST' + i),
        help='Host name ' + i)


args = parser.parse_args()

if args.noStandard and args.noSpecific:
    print('Nothing to do as you have specified both --noStandard and '
          '--noSpecific', file=sys.stderr)
    sys.exit(1)

username = args.username or environ.get('CHARITE_FIREWALL_USERNAME')

if username is None:
    print('You must either give a username via --username or else put your '
          'username into a CHARITE_FIREWALL_USERNAME environment variable',
          file=sys.stderr)
    sys.exit(1)

password = args.password or environ.get('CHARITE_FIREWALL_PASSWORD')

if password is None:
    password = getpass.getpass('Firewall password for %s: ' % username)


URL = 'http://firewall.charite.de:900/'
HEADERS = {
    'user-agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
                   'Gecko/20100101 Firefox/61.0')
}

# Convenience variables to make code logic clearer.
doStandard, doSpecific = (not args.noStandard, not args.noSpecific)


def enable(standardRules, hostData=None):
    """
    Request firewall destination/port opening.

    @param standardRules: If C{True} just request standard rules. Else
        request specific rules.
    @param hostData: A C{dict} whose keys are C{str} host names with
        values that are C{str} services. Only used if C{standardRules}
        is C{False}.
    """
    print('  Obtaining session id.')
    r = requests.get(URL, headers=HEADERS)

    # Pull the hidden ID form field out of the response. This is dirty, we
    # could instead parse the HTML response properly.
    match = re.search('<input type="hidden" name="ID" value="([0-9a-f]+)">',
                      r.text)
    if match:
        sessionId = match.group(1)
    else:
        print('Could not find ID in response text:\n%s' % r.text,
              file=sys.stderr)
        sys.exit(1)

    # Sanity check that the response format hasn't changed.
    STATE_STRING = '<input type="hidden" name="STATE" value="1">'
    if r.text.find(STATE_STRING) == -1:
        print('Did not find expected STATE string (%s) in response text:\n%s' %
              (STATE_STRING, r.text), file=sys.stderr)
        sys.exit(1)

    # Send our username.
    data = {
        'ID': sessionId,
        'STATE': '1',
        'DATA': username,
    }

    sleep()
    print('  Sending user name %s.' % username)
    r = requests.post(URL, headers=HEADERS, data=data)

    # Send our password.
    data = {
        'ID': sessionId,
        'STATE': '2',
        'DATA': password,
    }

    sleep()
    print('  Sending password.')
    r = requests.post(URL, headers=HEADERS, data=data)

    if standardRules:
        # Send that we want standard sign-on.  We should check that the form
        # value is actually 1.
        data = {
            'ID': sessionId,
            'STATE': '3',
            'DATA': '1',  # The form value for standard sign-on.
        }

        sleep()
        print('  Requesting standard sign-on rules.')
        r = requests.post(URL, headers=HEADERS, data=data)

    else:
        # Send that we want a specific sign-on.  We should check that the form
        # value is actually 3.
        data = {
            'ID': sessionId,
            'STATE': '3',
            'DATA': '3',  # The form value for specific sign-on.
        }

        sleep()
        print('  Requesting specific sign-on rules.')
        r = requests.post(URL, headers=HEADERS, data=data)

        # Send the host and service name.

        data = {
            'ID': sessionId,
            'STATE': '4',
        }

        data.update(hostData)

        sleep()
        print('  Sending requested host and service name(s).')
        r = requests.post(URL, headers=HEADERS, data=data)

        # Check that all requested hosts were permitted.

        for i in map(str, range(0, 10)):
            host = hostData['HOST' + i]
            if host:
                expected = 'Client Authorized for service %s on host %s' % (
                    hostData['SERVICE' + i], host)
                if r.text.find(expected) == -1:
                    print('Did not find expected success string (%s) in '
                          'response text:\n%s' % (expected, r.text),
                          file=sys.stderr)
                    sys.exit(1)

        print('  All requested host and services authenticated.')


# Request standard rules.
if doStandard:
    print('Requesting standard rules.')
    enable(standardRules=True)

if doSpecific:
    # Extract specific host and service names.
    hostData = {}
    hostFound = False

    for i in map(str, range(0, 10)):
        host = getattr(args, 'host' + i)

        if host:
            hostFound = True
            service = getattr(args, 'service' + i) or DEFAULT_SERVICE
        else:
            host = service = ''

        hostData['SERVICE' + i] = service
        hostData['HOST' + i] = host

    if hostFound:
        # Sleep if we just got done requesting standard rules.
        if doStandard:
            sleep()
        print('Requesting specific rules.')
        enable(standardRules=False, hostData=hostData)
    else:
        if not doStandard:
            print('Standard rules were not requested and there were no '
                  'specific hosts given, so nothing was done. Use --host0 or '
                  'set CHARITE_FIREWALL_HOST0 and CHARITE_FIREWALL_SERVICE0 '
                  '(0-9) in your environment to also request specific hosts '
                  'and services.', file=sys.stderr)
            sys.exit(1)
