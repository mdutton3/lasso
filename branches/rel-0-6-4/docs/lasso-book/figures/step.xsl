<?xml version="1.0"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:svg="http://www.w3.org/2000/svg">
 <xsl:output method="xml" encoding="UTF-8" indent="yes"/>

 <xsl:param name="stepno"/>

 <xsl:template match="svg:g[starts-with(@id, 'step')]">
  <xsl:variable name="n">
   <xsl:value-of select="substring-after(@id, 'step')"/>
  </xsl:variable>

  <xsl:choose>
   <xsl:when test="number($n) &gt; number($stepno)">
    <xsl:copy> <xsl:attribute name="style">opacity:0;</xsl:attribute><xsl:apply-templates select="node()|@*"/> </xsl:copy>
   </xsl:when>
   <xsl:when test="number($n) &lt; number($stepno)">
    <xsl:copy> <xsl:attribute name="style">opacity:0.5;</xsl:attribute><xsl:apply-templates select="node()|@*"/> </xsl:copy>
   </xsl:when>
   <xsl:otherwise>
    <xsl:copy> <xsl:apply-templates select="node()|@*"/> </xsl:copy>
   </xsl:otherwise>
  </xsl:choose>
 </xsl:template>

 <xsl:template match="node()|@*">
  <xsl:copy>
   <xsl:apply-templates select="node()|@*"/>
  </xsl:copy>
 </xsl:template>

</xsl:stylesheet>
