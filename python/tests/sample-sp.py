#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# Lasso Simulator
# By: Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import logging
from optparse import OptionParser
import sys

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso

import assertions
import builtins
import http
import liberty

applicationCamelCaseName = 'LassoSimulator'
applicationPublicName = 'Lasso Simulator'
applicationVersion = '(Unreleased CVS Version)'
logger = None


class HttpRequestHandlerMixin:
    realm = '%s Web Site' % applicationPublicName
    server_version = '%s/%s' % (applicationCamelCaseName, applicationVersion)

    def version_string(self):
        return '%s %s' % (applicationPublicName, applicationVersion)


class HttpRequestHandler(HttpRequestHandlerMixin, http.HttpRequestHandler):
    pass


class HttpsRequestHandler(HttpRequestHandlerMixin, http.HttpsRequestHandler):
    pass


def main():
    # Parse command line options.
    parser = OptionParser(version = '%%prog %s' % applicationVersion)
    parser.add_option(
        '-c', '--config', metavar = 'FILE', dest = 'configurationFilePath',
        help = 'specify an alternate configuration file',
        default = '/etc/lasso-simulator/config.xml')
    parser.add_option(
        '-d', '--daemon', dest = 'daemonMode', help = 'run main process in background',
        action = 'store_true', default = False)
    parser.add_option(
        '-D', '--debug', dest = 'debugMode', help = 'enable program debugging',
        action = 'store_true', default = False)
    parser.add_option(
        '-l', '--log', metavar = 'FILE', dest = 'logFilePath', help = 'specify log file',
        default = '/dev/null')
    parser.add_option(
        '-L', '--log-level', metavar = 'LEVEL', dest = 'logLevel',
        help = 'specify log level (debug, info, warning, error, critical)', default = 'info')
    (options, args) = parser.parse_args()
    if options.logLevel.upper() not in logging._levelNames:
        raise Exception('Unknown log level: "%s"' % options.logLevel)

    # Configure logger.
    logger = logging.getLogger()
    if options.debugMode and not options.daemonMode:
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.FileHandler(options.logFilePath)
    formatter = logging.Formatter('%(asctime)s %(levelname)-9s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging._levelNames[options.logLevel.upper()])
    builtins.set('logger', logger)

    site = liberty.ServiceProvider('https://sp1:2006/')
    site.providerId = 'https://sp1/metadata'
    site.idpSite = liberty.IdentityProvider('https://idp1:1998/')
    site.idpSite.providerId = 'https://idp1/metadata'

    lassoServer = lasso.Server.new(
        '../../tests/data/sp1-la/metadata.xml',
        None, # '../../tests/data/sp1-la/public-key.pem' is no more used
        '../../tests/data/sp1-la/private-key-raw.pem',
        '../../tests/data/sp1-la/certificate.pem',
        lasso.signatureMethodRsaSha1)
    lassoServer.add_provider(
        '../../tests/data/idp1-la/metadata.xml',
        '../../tests/data/idp1-la/public-key.pem',
        '../../tests/data/ca1-la/certificate.pem')
    site.lassoServerDump = lassoServer.dump()
    failUnless(site.lassoServerDump)
    lassoServer.destroy()

    site.certificateAbsolutePath = '../../tests/data/sp1-ssl/certificate.pem'
    site.privateKeyAbsolutePath = '../../tests/data/sp1-ssl/private-key-raw.pem'
    site.peerCaCertificateAbsolutePath = '../../tests/data/ca1-ssl/certificate.pem'

    site.newUser('Nicolas')
    site.newUser('Romain')
    site.newUser('Valery')
    # Christophe Nowicki has no account on service provider.
    site.newUser('Frederic')

    HttpRequestHandlerMixin.site = site # Directly a site, not a server => no virtual host.
##     httpServer = http.HttpServer(('sp1', 2005), HttpRequestHandler)
##     logger.info('Serving HTTP on %s port %s...' % httpServer.socket.getsockname())
    httpServer = http.HttpsServer(
        ('sp1', 2006),
        HttpsRequestHandler,
        site.privateKeyAbsolutePath, # Server private key
        site.certificateAbsolutePath, # Server certificate
        site.peerCaCertificateAbsolutePath, # Clients certification authority certificate
        None, # sslCertificateChainFile see mod_ssl, ssl_engine_init.c, line 852
        None, # sslVerifyClient http://www.modssl.org/docs/2.1/ssl_reference.html#ToC13
        )
    logger.info('Serving HTTPS on %s port %s...' % httpServer.socket.getsockname())
    try:
        httpServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
if __name__ == '__main__':
    main()
