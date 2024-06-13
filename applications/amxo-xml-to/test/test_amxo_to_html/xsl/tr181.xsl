<?xml version="1.0" encoding="UTF-8" ?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dm="urn:broadband-forum-org:cwmp:datamodel-1-5" xmlns:dmr="urn:broadband-forum-org:cwmp:datamodel-report-0-1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:odl="http://www.softathome.com/odl">

<xsl:output method="xml" indent="yes" encoding="utf-8"/>

<xsl:template match="/odl:datamodel-set/odl:datamodel">
	
<xsl:element name="description">
    TR-069 Device:2.7 Root Object definition
    November 2013
    Added ZigBee data model, Provider Bridge data model, and various other items
  </xsl:element>

	<xsl:element name="model">
	<xsl:attribute name="name">Device:2.7></xsl:attribute>
	<xsl:attribute name="base">Device:2.6></xsl:attribute>
	<xsl:apply-templates select="odl:object"></xsl:apply-templates>        
	</xsl:element>
	
</xsl:template>

<xsl:template match="odl:object">
	<xsl:element name="object">
	<xsl:attribute name="base"><xsl:value-of select="@odl:path" /></xsl:attribute>
	<xsl:apply-templates select="odl:parameter"></xsl:apply-templates>  
	<xsl:apply-templates select="odl:object"></xsl:apply-templates>           
	</xsl:element>
</xsl:template>

<xsl:template match="odl:validator">
<xsl:variable name="type" select="@odl:type"/>
<xsl:choose>
	<xsl:when test="$type = 'enum'">
		<xsl:for-each select="odl:value">
		  <xsl:element name="enumeration"> 
		  <xsl:attribute name="value"><xsl:value-of select="current()"/> </xsl:attribute>
		  </xsl:element>
		 </xsl:for-each>
	</xsl:when>
	<xsl:when test="$type = 'minimum'">
		<xsl:element name="range"> 
		<xsl:attribute name="minInclusive"><xsl:value-of select="@odl:min"/> </xsl:attribute>
		</xsl:element>
	</xsl:when>
	<xsl:when test="$type = 'maximum'">
		<xsl:element name="range"> 
		<xsl:attribute name="maxInclusive"><xsl:value-of select="@odl:max"/> </xsl:attribute>
		</xsl:element>
	</xsl:when>
	<xsl:when test="$type = 'range'">
		<xsl:element name="range"> 
		<xsl:attribute name="minInclusive"><xsl:value-of select="@odl:min"/> </xsl:attribute>
		<xsl:attribute name="maxInclusive"><xsl:value-of select="@odl:max"/> </xsl:attribute>
		</xsl:element>
	</xsl:when>
	<xsl:otherwise></xsl:otherwise>
</xsl:choose>
</xsl:template>

<xsl:template match="odl:parameter">
	<xsl:element name="parameter">
	<xsl:attribute name="base"><xsl:value-of select="@odl:name" /></xsl:attribute>
	<xsl:attribute name="access">
		<xsl:variable name="rw" select="@odl:read-only"/>
		<xsl:choose>
			<xsl:when test="$rw = 'true'">readOnly</xsl:when>
			<xsl:otherwise>readWrite</xsl:otherwise>
		</xsl:choose>		
	</xsl:attribute>
	<xsl:variable name="type" select="@odl:type"/>
	<xsl:element name="description"></xsl:element>
	<xsl:element name="syntax">
	<xsl:choose>
		<xsl:when test="$type = 'uint32'"><xsl:element name="unsignedInt">
			<xsl:apply-templates select="odl:validator"></xsl:apply-templates>  
		</xsl:element>
		</xsl:when>
		<xsl:when test="$type = 'bool'"><xsl:element name="boolean"></xsl:element></xsl:when>
		<xsl:when test="$type = 'string'"><xsl:element name="string">
			<xsl:apply-templates select="odl:validator"></xsl:apply-templates>  
		</xsl:element>       
		</xsl:when>
		<xsl:otherwise><xsl:element name="{$type}"></xsl:element></xsl:otherwise>
		 
		
	</xsl:choose>			
	</xsl:element>
	</xsl:element>
	
</xsl:template>

</xsl:stylesheet>

