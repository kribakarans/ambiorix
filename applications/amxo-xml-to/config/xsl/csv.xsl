<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dm="urn:broadband-forum-org:cwmp:datamodel-1-5" xmlns:dmr="urn:broadband-forum-org:cwmp:datamodel-report-0-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:odl="http://www.softathome.com/odl">
  <xsl:output method="text" encoding="utf-8" />

  <xsl:variable name="quote" select="'&quot;'" />
  <xsl:variable name="break" select="'&#xA;'" />
  <xsl:variable name="apos"><xsl:text>'</xsl:text></xsl:variable>

<xsl:template match="/odl:datamodel-set/odl:datamodel">
    <xsl:element name="model">
    <xsl:text>Summary,Description,Name,DataType,Rights&#xA;</xsl:text>
    <xsl:apply-templates select="odl:object"></xsl:apply-templates>
    </xsl:element>
</xsl:template>

  <xsl:template match="odl:object">
    <xsl:value-of select="concat($quote, @odl:path, $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:apply-templates select="odl:description"></xsl:apply-templates>
    <xsl:text>,</xsl:text>
    <xsl:value-of select="concat($quote, @odl:path, $quote)" />
    <xsl:text>,"object",</xsl:text>
    <xsl:text>&#xA;</xsl:text>
    <xsl:apply-templates select="odl:parameter"></xsl:apply-templates>
    <xsl:apply-templates select="odl:function"></xsl:apply-templates>
    <xsl:apply-templates select="odl:object"></xsl:apply-templates>
  </xsl:template>

  <xsl:template match="odl:description">
    <xsl:value-of select="concat($quote, translate(normalize-space(), $quote, $apos), $quote)" />
  </xsl:template>

  <xsl:template match="odl:parameter">
    <xsl:value-of select="concat($quote, @odl:path, $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:apply-templates select="odl:description"></xsl:apply-templates>
    <xsl:text>,</xsl:text>
    <xsl:value-of select="concat($quote, @odl:name, $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:value-of select="concat($quote, @odl:type, $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:choose>
      <xsl:when test="@odl:read-only = 'true'">
        <xsl:text>"R"</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>"RW"</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>&#xA;</xsl:text>
  </xsl:template>

  <xsl:template match="odl:function">
    <xsl:value-of select="concat($quote, @odl:path, '()', $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:apply-templates select="odl:description"></xsl:apply-templates>
    <xsl:text>,</xsl:text>
    <xsl:value-of select="concat($quote, @odl:name, '()', $quote)" />
    <xsl:text>,"command",</xsl:text>
    <xsl:text>&#xA;</xsl:text>
    <xsl:apply-templates select="odl:argument"></xsl:apply-templates>
  </xsl:template>

  <xsl:template match="odl:argument">
    <xsl:value-of select="concat($quote, @odl:path, $quote)" />
    <xsl:text>,</xsl:text>
    <xsl:apply-templates select="odl:description"></xsl:apply-templates>
    <xsl:text>,</xsl:text>
    <xsl:choose>
      <xsl:when test="@odl:in = 'true'">
        <xsl:value-of select="concat($quote, '=&gt; ', @odl:name, $quote)" />
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="concat($quote, '&lt;= ', @odl:name, $quote)" />
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text>,</xsl:text>
    <xsl:value-of select="concat($quote, @odl:type, $quote)" />
    <xsl:text>&#xA;</xsl:text>
  </xsl:template>

</xsl:stylesheet>
