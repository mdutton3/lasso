/*
 * ColdFusionLasso -- ColdFusion bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Emmanuel Raviart <eraviart@entrouvert.com>
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
 * Simple wrapper for JLasso, to ease its use by ColdFusion applications.
 *
 * To use it:
 * $ javac -classpath ../lasso-devel/java/target/lasso.jar CFLasso.java
 * Edit ColdFusion file bin/jvm.config:
 *   - Add libjlasso.so directory to java.library.path variable.
 *   - Add classes directory to java.class.path variable.
 */


public class CFLasso {
    protected com.entrouvert.lasso.LassoServer getServerContext() {
        com.entrouvert.lasso.LassoServer serverContext = new com.entrouvert.lasso.LassoServer(
            "/home/manou/projects/lasso/lasso-devel/examples/data/sp-metadata.xml",
            "/home/manou/projects/lasso/lasso-devel/examples/data/sp-public-key.pem",
            "/home/manou/projects/lasso/lasso-devel/examples/data/sp-private-key.pem",
            "/home/manou/projects/lasso/lasso-devel/examples/data/sp-crt.pem",
            com.entrouvert.lasso.Lasso.signatureMethodRsaSha1);
        serverContext.addProvider(
            "/home/manou/projects/lasso/lasso-devel/examples/data/idp-metadata.xml",
            "/home/manou/projects/lasso/lasso-devel/examples/data/idp-public-key.pem",
            "/home/manou/projects/lasso/lasso-devel/examples/data/ca-crt.pem");
	return serverContext;
    }

    public String login(String relayState) {
	com.entrouvert.lasso.LassoAuthnRequest authnRequest;
	com.entrouvert.lasso.LassoLogin loginContext;
	com.entrouvert.lasso.LassoServer serverContext;
	String authnRequestUrl;

	com.entrouvert.lasso.Lasso.init();

	serverContext = getServerContext();
        loginContext = new com.entrouvert.lasso.LassoLogin(serverContext, null);
        loginContext.initAuthnRequest("https://identity-provider:1998/liberty-alliance/metadata");
	authnRequest = (com.entrouvert.lasso.LassoAuthnRequest) loginContext.getRequest();
        authnRequest.setPassive(false);
        authnRequest.setNameIdPolicy(com.entrouvert.lasso.Lasso.libNameIdPolicyTypeFederated);
        authnRequest.setConsent(com.entrouvert.lasso.Lasso.libConsentObtained);
	if (relayState != null)
	    authnRequest.setRelayState(relayState);
        loginContext.buildAuthnRequestMsg();
        authnRequestUrl = loginContext.getMsgUrl();

	com.entrouvert.lasso.Lasso.shutdown();

	return authnRequestUrl;
    }

    static public void main(String [] args) {
	CFLasso lasso = new CFLasso();
	String ssoUrl = lasso.login(null);
	System.out.print("Identity provider single sign-on URL = ");
	System.out.println(ssoUrl);
    }
}
