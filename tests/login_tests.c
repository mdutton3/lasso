/*
 * Lasso library C unit tests
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Author: Emmanuel Raviart <eraviart@entrouvert.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


/*
gcc -g -O2 -I./.. `pkg-config gobject-2.0 --cflags` `pkg-config libxml-2.0 --cflags` -L../lasso/.libs -llasso `pkg-config gobject-2.0 --libs` `pkg-config libxml-2.0 --libs` -DXMLSEC_CRYPTO=\"openssl\" -DXMLSEC_LIBXML_260=1 -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO_OPENSSL=1 -I/usr/include/xmlsec1 -I/usr/include/libxml2 -L/usr/lib -L/usr/local/lib -lxmlsec1-openssl -lxmlsec1 -lxslt -lxml2 -lz -lpthread -lm -lssl -lcrypto -ldl login_tests.c -o login_tests
*/


#include <lasso/lasso.h>


char *generateIdentityProviderContextDump() {
  LassoServer *serverContext = lasso_server_new(
      "../examples/data/idp-metadata.xml",
      "../examples/data/idp-public-key.pem",
      "../examples/data/idp-private-key.pem",
      "../examples/data/idp-crt.pem",
      lassoSignatureMethodRsaSha1);
  lasso_server_add_provider(
      serverContext,
      "../examples/data/sp-metadata.xml",
      "../examples/data/sp-public-key.pem",
      "../examples/data/ca-crt.pem");
  char *serverContextDump = lasso_server_dump(serverContext);
  return serverContextDump;
}

void test01_generateServersContextDumps() {
  char *identityProviderContextDump = generateIdentityProviderContextDump();
  printf("SUCCESS = %s\n", identityProviderContextDump);
/*   char *serviceProviderContextDump = generateServiceProviderContextDump(); */
/*   assertNotNull(serviceProviderContextDump); */
}


void test02_serviceProviderLogin() {
}


int main() {
  lasso_init();

  test01_generateServersContextDumps();
  test02_serviceProviderLogin();

  lasso_shutdown();
}
