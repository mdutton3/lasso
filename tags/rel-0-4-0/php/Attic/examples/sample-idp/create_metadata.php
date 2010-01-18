<?php
/*  
 * Identity Provider Example -- Form for creating Service Provider Metadata
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

 require_once 'HTML/QuickForm.php';

  $form = new HTML_QuickForm('frm');

  $form->setDefaults(array(
    'providerID' => 'https://', 
    'AssertionConsumerService' => 'https://', 
    'SoapEndpoint' => 'https://', 
    'SingleLogoutService' => 'https://', 
    'RegisterNameIdentifierService' => 'https://', 
	'AuthnRequestsSigned' => 1,
	'filename' => getcwd().'/metadata.xml'
  ));
 
  $form->addElement('header', null, 'Create Liberty Alliance Metadata for an Service Provider');
  $form->addElement('text', 'providerID', 'providerID:', array('size' => 60, 'maxlength' => 255));

  $form->addElement('text', 'AssertionConsumerService', 'AssertionConsumerService:', array('size' => 60, 'maxlength' => 255));

  $form->addElement('text', 'SingleLogoutService', 'SingleLogoutService:', array('size' => 60, 'maxlength' => 255));
  $form->addElement('select', 'SingleLogoutProtocolProfile', 'SingleLogoutProtocolProfile:', array('http://projectliberty.org/profiles/slo-idp-soap'));

  $form->addElement('text', 'RegisterNameIdentifierService', 'RegisterNameIdentifierService:', array('size' => 60, 'maxlength' => 255));
  $form->addElement('select', 'RegisterNameIdentifierProtocolProfile', 'RegisterNameIdentifierProtocolProfile:', array('http://projectliberty.org/profiles/rni-sp-soap'));

  $form->addElement('text', 'SoapEndpoint', 'SoapEndpoint:', array('size' => 60, 'maxlength' => 255));
  $form->addElement('checkbox', 'AuthnRequestsSigned', 'Authn Requests must be signed? :', '');

  $form->addElement('textarea', 'metadata', 'Metadata:', array('cols' => 60, 'rows' => 15));
  $form->addElement('text', 'filename', 'Filename:', array('size' => 60, 'maxlength' => 255));
  
  $button[] = &HTML_QuickForm::createElement('button', null, 'Preview', array('onclick' => "write_metadata_preview();"));
  $button[] = &HTML_QuickForm::createElement('submit', null, 'Write Metadata');
  
  $form->addGroup($button, null, null, '&nbsp;', false);
  
  if ($form->validate()) {

	$xml = "<?xml version=\"1.0\"?>
<EntityDescriptor providerID=\"". $form->exportValue('providerID') ."\" xmlns=\"urn:liberty:metadata:2003-08\">
<SPDescriptor>
    <AssertionConsumerServiceURL id=\"AssertionConsumerServiceURL1\" isDefault=\"true\">" . $form->exportValue('AssertionConsumerService') . "</AssertionConsumerServiceURL>\n 
    <SingleLogoutServiceURL>" . $form->exportValue('SingleLogoutService') . "</SingleLogoutServiceURL>
    <SingleLogoutProtocolProfile>" . $form->exportValue('SingleLogoutProtocolProfile') . "</SingleLogoutProtocolProfile>\n
    <RegisterNameIdentifierServiceURL>" . $form->exportValue('RegisterNameIdentifierService')  . "</RegisterNameIdentifierServiceURL>
    <RegisterNameIdentifierProtocolProfile>" . $form->exportValue('RegisterNameIdentifierProtocolProfile') . "</RegisterNameIdentifierProtocolProfile>\n
    <SoapEndpoint>" . $form->exportValue('SoapEndpoint') . "</SoapEndpoint>\n
    <AuthnRequestsSigned>" . (($form->exportValue('AuthnRequestsSigned')) ? 'true' : 'false') . "</AuthnRequestsSigned>
</SPDescriptor>
</EntityDescriptor>";


	if (($fd = fopen($form->exportValue('filename'), "w")))
	  {
		  fwrite($fd, $xml);
		  fclose($fd);
  	  }
  	else
	  die("Could not write metadata file :" . $form->exportValue('filename'));
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<body onLoad="window.close()">
</body>
</html>
<?php
	exit;
  }
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<script language="JavaScript" type="text/javascript">
<!-- 

  function write_metadata_preview(popurl)
  {
	frm = document.frm;
	
	frm.metadata.value = 	
	'<\?xml version=\"1.0\"\?>\n' +
	'<EntityDescriptor\n' +
    'providerID="' + frm.providerID.value + '\"\n' +
    'xmlns=\"urn:liberty:metadata:2003-08\">\n' +
	'<SPDescriptor>\n' +
    '<AssertionConsumerServiceURL id=\"AssertionConsumerServiceURL1\" isDefault=\"true\">' +
	frm.AssertionConsumerService.value + '</AssertionConsumerServiceURL>\n' +
    '<SingleLogoutServiceURL>' + frm.SingleLogoutService.value + '</SingleLogoutServiceURL>\n' +
    '<SingleLogoutProtocolProfile>' +  frm.SingleLogoutProtocolProfile.options[frm.SingleLogoutProtocolProfile.value].text + '</SingleLogoutProtocolProfile>\n' +
    '<RegisterNameIdentifierServiceURL>' + frm.RegisterNameIdentifierService.value + '</RegisterNameIdentifierServiceURL>\n' +
    '<RegisterNameIdentifierProtocolProfile>' + frm.RegisterNameIdentifierProtocolProfile.options[frm.RegisterNameIdentifierProtocolProfile.value].text + '</RegisterNameIdentifierProtocolProfile>\n' +
    '<SoapEndpoint>' + frm.SoapEndpoint.value + '</SoapEndpoint>\n' +
    '<AuthnRequestsSigned>' + ((frm.AuthnRequestsSigned.value) ? 'true' : 'false') + '</AuthnRequestsSigned>\n' +
	'</SPDescriptor>\n' +
    '</EntityDescriptor>';
  }
//-->
</script>
</head>
<body>
<?php
  $form->display();
?>
<br>
<p>Copyright &copy; 2004 Entr'ouvert</p>
</body>
</html>
