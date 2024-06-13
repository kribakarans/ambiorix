<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:odl="http://www.softathome.com/odl"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="str">

  <xsl:output method="xml"
              encoding="utf-8"
              omit-xml-declaration="no"
              indent="yes"/> 

  <xsl:template match="/">
    <odl:datamodel-set>
      <xsl:for-each select="str:tokenize($files, ',')">
        <xsl:apply-templates select="document(.)/odl:datamodel-set/odl:datamodel"/>
        <xsl:apply-templates select="document(.)/odl:datamodel-set/odl:types"/>
        <xsl:apply-templates select="document(.)/odl:datamodel-set/odl:locations"/>
      </xsl:for-each>
    </odl:datamodel-set>
  </xsl:template>

  <xsl:template name="identity" match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>

