/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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

package com.entrouvert.lasso;

public class LassoServer extends LassoProvider { // LassoServer

    public LassoServer(String metadataFilePath,
                       String publicKeyFilePath,
                       String privateKeyFilePath,
                       String certificateFilePath,
                       int lassoSignatureMethodRsaSha1){
        init(metadataFilePath, publicKeyFilePath, privateKeyFilePath,
            certificateFilePath, lassoSignatureMethodRsaSha1);
    }

    public LassoServer(String dump){
        initFromDump(dump);
    }

    /**
    * This method must set the c_lasso_object. If creation of LassoServer failed
    * then c_lasso_object's value is 0.
    */
    native protected void init(String metadataFilePath,
                               String publicKeyFilePath,
                               String privateKeyFilePath,
                               String certificateFilePath,
                               int lassoSignatureMethodRsaSha1);

    protected void finalize(){
        destroy();
    }

    /**
    * This method must set the c_lasso_object. If creation of LassoServer failed
    * then c_lasso_object's value is 0.
    */
    native protected void initFromDump(String dump);

    native public void addProvider(String idpMetadataFilePath,
                                   String idpPublicKeyFilePath,
                                   String idpCaCertificateFilePath);

    native public String dump();

    native protected void destroy();

} // LassoServer

