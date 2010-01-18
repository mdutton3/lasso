/* $Id: disco_svc_metadata.i,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: See AUTHORS file in top-level directory.
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

#ifndef SWIGPHP4
%rename(IdWsf2DiscoSvcMetadata) LassoIdWsf2DiscoSvcMetadata;
#endif
typedef struct {

#ifndef SWIGPHP4
  /* XXX: SWIG 1.3.31 and more fails to compile the PHP 4 binding it
     generates if this * part is present */

#if !defined(SWIG_PHP_RENAMES) && !defined(SWIGCSHARP) && !defined(SWIGJAVA)
	/* "abstract" is a reserved word in PHP, C# and Java. */
	%rename(abstract) Abstract;
#endif
	char *Abstract;

#endif /* !SWIGPHP4 */

#ifndef SWIGPHP4
	%rename(providerID) ProviderID;
#endif
	char *ProviderID;
	char *svcMDID;
} LassoIdWsf2DiscoSvcMetadata;
%extend LassoIdWsf2DiscoSvcMetadata {

	/* Constructor, Destructor & Static Methods */
	LassoIdWsf2DiscoSvcMetadata();
	~LassoIdWsf2DiscoSvcMetadata();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2DiscoSvcMetadata lasso_idwsf2_disco_svc_metadata_new
#define delete_LassoIdWsf2DiscoSvcMetadata(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2DiscoSvcMetadata_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

