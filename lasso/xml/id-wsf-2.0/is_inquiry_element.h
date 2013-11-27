/* $Id: is_inquiry_element.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_IDWSF2_IS_INQUIRY_ELEMENT_H__
#define __LASSO_IDWSF2_IS_INQUIRY_ELEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "is_help.h"

#define LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT (lasso_idwsf2_is_inquiry_element_get_type())
#define LASSO_IDWSF2_IS_INQUIRY_ELEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT, \
		LassoIdWsf2IsInquiryElement))
#define LASSO_IDWSF2_IS_INQUIRY_ELEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT, \
		LassoIdWsf2IsInquiryElementClass))
#define LASSO_IS_IDWSF2_IS_INQUIRY_ELEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT))
#define LASSO_IS_IDWSF2_IS_INQUIRY_ELEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT))
#define LASSO_IDWSF2_IS_INQUIRY_ELEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT, \
		LassoIdWsf2IsInquiryElementClass))


typedef struct _LassoIdWsf2IsInquiryElement LassoIdWsf2IsInquiryElement;
typedef struct _LassoIdWsf2IsInquiryElementClass LassoIdWsf2IsInquiryElementClass;


struct _LassoIdWsf2IsInquiryElement {
	LassoNode parent;

	/*< public >*/
	/* elements */
	/* XXX */ void *Help;
	char *Hint;
	char *Label;
	char *Value;
	/* attributes */
	char *name;
};


struct _LassoIdWsf2IsInquiryElementClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_is_inquiry_element_get_type(void);
LASSO_EXPORT LassoIdWsf2IsInquiryElement* lasso_idwsf2_is_inquiry_element_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_IS_INQUIRY_ELEMENT_H__ */
