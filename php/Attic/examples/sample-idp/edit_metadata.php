<?php
/*  
 * Identity Provider Example -- Setup
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Christophe Nowicki <cnowicki@easter-eggs.com>
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

  $filename = $_GET['filename'];
  if (!empty($filename) && file_exists($filename))
  {
	require_once 'HTML/QuickForm.php';

	$form = new HTML_QuickForm('frm');

	$form->addElement('header', null, 'Edit Liberty Alliance Metadata for an Service Provider');
	$form->addElement('text', 'providerID', 'providerID:', array('size' => 60, 'maxlength' => 255));

	$form->addElement('text', 'AssertionConsumerService', 'AssertionConsumerService:', array('size' => 60, 'maxlength' => 255));

	$form->addElement('text', 'SingleLogoutService', 'SingleLogoutService:', array('size' => 60, 'maxlength' => 255));
	$form->addElement('select', 'SingleLogoutProtocolProfile', 'SingleLogoutProtocolProfile:', array('http://projectliberty.org/profiles/slo-idp-soap'));

	$form->addElement('text', 'RegisterNameIdentifierService', 'RegisterNameIdentifierService:', array('size' => 60, 'maxlength' => 255));
	$form->addElement('select', 'RegisterNameIdentifierProtocolProfile', 'RegisterNameIdentifierProtocolProfile:', array('http://projectliberty.org/profiles/rni-sp-soap'));

	$form->addElement('text', 'SoapEndpoint', 'SoapEndpoint:', array('size' => 60, 'maxlength' => 255));
	$form->addElement('checkbox', 'AuthnRequestsSigned', 'Authn Requests must be signed? :', '');
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
  <title>Edit Metadata</title>
</head>
<body>
<?php
  $form->display();
?>
</body>
</html>
<?php
  }
?>
