/* $Id$
 *
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.labs.libre-entreprise.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
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

/* *
 * LassoRequest.java
 *
 * Created: 17 juil. 2004
 *
 * @author Benjamin Poussin <poussin@codelutin.com>
 * @version $Revision$
 *
 * Mise a jour: $Date$
 * par : $Author$
 */

package com.entrouvert.lasso;

public class LassoAuthnRequest extends LassoNode { // LassoAuthnRequest

    public LassoAuthnRequest(String providerID){
        init(providerID);
    }

    native protected void init(String providerID);

    // From LassoLibAuthnRequest

    native public void setAffiliationID(String affiliationId);
    native public void setassertionConsumerServiceID(String assertionConsumerServiceID);
    native public void setContent(String content);
    native public void setForceAuthn(boolean val);
    native public void setPassive(boolean val);
    native public void setNameIdPolicy(String val);
    native public void setProtocolProfile(String val);
    native public void setproviderID(String val);
    native public void setRelayState(String val);

    // not implemented
    // lasso_lib_authn_request_set_requestAuthnContext(LassoLibRequestAuthnContext*)
    // lasso_lib_authn_request_set_scoping(LassoLibScoping*)

} // LassoAuthnRequest

