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

    site = liberty.ServiceProvider('https://service-provider/')
    site.providerId = 'https://service-provider/metadata'
    site.idpSite = liberty.IdentityProvider('https://identity-provider/')
    site.idpSite.providerId = 'https://identity-provider/metadata'

    lassoServer = lasso.Server.new(
        '../../examples/data/sp-metadata.xml',
        '../../examples/data/sp-public-key.pem',
        '../../examples/data/sp-private-key.pem',
        '../../examples/data/sp-crt.pem',
        lasso.signatureMethodRsaSha1)
    lassoServer.add_provider(
        '../../examples/data/idp-metadata.xml',
        '../../examples/data/idp-public-key.pem',
        '../../examples/data/ca-crt.pem')
    site.lassoServerDump = lassoServer.dump()
    failUnless(site.lassoServerDump)
    lassoServer.destroy()

    site.certificateAbsolutePath = '../../examples/data/sp-ssl-crt.pem'
    site.privateKeyAbsolutePath = '../../examples/data/sp-ssl-private-key.pem'
    site.peerCaCertificateAbsolutePath = '../../examples/data/ca-ssl-crt.pem'

    site.newUser('Nicolas')
    site.newUser('Romain')
    site.newUser('Valery')
    # Christophe Nowicki has no account on service provider.
    site.newUser('Frederic')

    HttpRequestHandlerMixin.site = site # Directly a site, not a server => no virtual host.
##     httpServer = http.HttpServer(('127.0.0.3', 80), HttpRequestHandler)
##     logger.info('Serving HTTP on %s port %s...' % httpServer.socket.getsockname())
    httpServer = http.HttpsServer(
        ('127.0.0.3', 443),
        HttpsRequestHandler,
        '../../examples/data/sp-ssl-private-key.pem', # Server private key
        '../../examples/data/sp-ssl-crt.pem', # Server certificate
        '../../examples/data/ca-ssl-crt.pem', # Clients certification authority certificate
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
