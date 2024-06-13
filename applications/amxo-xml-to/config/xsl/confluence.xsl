<?xml version="1.0"?>

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:odl="http://www.softathome.com/odl"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="str"
                exclude-result-prefixes="odl">

  <xsl:output method="html"
              encoding="string"
              omit-xml-declaration="yes"
              indent="no"/>
  <xsl:strip-space elements="*"/>

  <xsl:template match="/">
    <xsl:text>|| Name || Type || W/P/V || Description || Legal Values/Default || Action on Add/Delete/Modify || Version ||&#10;</xsl:text>
    <xsl:apply-templates select="//odl:object"/>
    <xsl:if test="//odl:types/odl:type">
      <xsl:text>
h1. Types
</xsl:text>
      <xsl:apply-templates select="//odl:type"/>
    </xsl:if>
  </xsl:template>

  <xsl:template match="odl:object">
    <xsl:text>|| </xsl:text>
    <xsl:call-template name="bbf-path"/>
    <xsl:text> || Object || </xsl:text>
    <xsl:choose>
      <xsl:when test="@odl:read-only"><xsl:text>R</xsl:text></xsl:when>
      <xsl:otherwise><xsl:text>RW</xsl:text></xsl:otherwise>
    </xsl:choose>
    <xsl:if test="@odl:persistent"><xsl:text>P</xsl:text></xsl:if>
    <xsl:text> || </xsl:text>
    <xsl:call-template name="description"/>
    <xsl:text> || -- || </xsl:text>
    <xsl:if test="odl:add-description">
      <xsl:text>*on add*: </xsl:text>
      <xsl:value-of select="normalize-space(odl:add-description)"/>
      <xsl:if test="odl:delete-description or odl:update-description">
        <xsl:text>\\
</xsl:text>
      </xsl:if>
    </xsl:if>
    <xsl:if test="odl:delete-description">
      <xsl:text>*on delete*: </xsl:text>
      <xsl:value-of select="normalize-space(odl:delete-description)"/>
      <xsl:if test="odl:update-description">
        <xsl:text>\\
</xsl:text>
      </xsl:if>
    </xsl:if>
    <xsl:if test="odl:update-description">
      <xsl:text>*on modify*: </xsl:text>
      <xsl:value-of select="normalize-space(odl:update-description)"/>
    </xsl:if>
    <xsl:text> || </xsl:text>
    <xsl:choose>
      <xsl:when test="odl:version-description">
        <xsl:value-of select="normalize-space(odl:version-description)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$version"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> ||&#10;</xsl:text>
    <xsl:apply-templates select="odl:parameter|odl:function"/>
  </xsl:template>

  <xsl:template match="odl:parameter">
    <xsl:text>| </xsl:text>
    <xsl:value-of select="@odl:name"/>
    <xsl:text> | </xsl:text>
    <xsl:value-of select="@odl:type"/>
    <xsl:text> | </xsl:text>
    <xsl:choose>
      <xsl:when test="@odl:read-only"><xsl:text>R</xsl:text></xsl:when>
      <xsl:otherwise><xsl:text>RW</xsl:text></xsl:otherwise>
    </xsl:choose>
    <xsl:if test="@odl:persistent"><xsl:text>P</xsl:text></xsl:if>
    <xsl:if test="@odl:volatile"><xsl:text>V</xsl:text></xsl:if>
    <xsl:text> | </xsl:text>
    <xsl:call-template name="description"/>
    <xsl:text> | </xsl:text>
    <xsl:choose>
      <xsl:when test="@odl:instance-counter">
        <xsl:text>*Instance counter for*: </xsl:text>
        <xsl:value-of select="@odl:counted-object"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text>*default*: </xsl:text>
        <xsl:value-of select="normalize-space(odl:default)"/>
        <xsl:if test="odl:validator">
            <xsl:text>\\
</xsl:text>
          <xsl:text>*legal values*: </xsl:text>
          <xsl:apply-templates select="odl:validator"/>
        </xsl:if>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> | </xsl:text>
    <xsl:choose>
      <xsl:when test="odl:update-description">
        <xsl:text>*on modify*: </xsl:text>
        <xsl:value-of select="normalize-space(odl:update-description)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text> -- </xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> | </xsl:text>
    <xsl:choose>
      <xsl:when test="odl:version-description">
        <xsl:value-of select="normalize-space(odl:version-description)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$version"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> |&#10;</xsl:text>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='enum']">
    <xsl:for-each select="odl:value">
      <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
      <xsl:text>&quot;</xsl:text><xsl:value-of select="."/><xsl:text>&quot;</xsl:text>
    </xsl:for-each>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='range']">
    <xsl:value-of select="@odl:min"/>
    <xsl:text> &#60; x &#60; </xsl:text>
    <xsl:value-of select="@odl:max"/>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='minimum']">
    <xsl:value-of select="@odl:min"/>
    <xsl:text> &#60; x </xsl:text>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='maximum']">
    <xsl:text>x &#60; </xsl:text>
    <xsl:value-of select="@odl:max"/>
  </xsl:template>

  <xsl:template match="odl:function">
    <xsl:text>| </xsl:text>
    <xsl:value-of select="@odl:name"/>
    <xsl:text>() | function | -- | </xsl:text>
    <xsl:text>_</xsl:text><xsl:value-of select="odl:return/@odl:type"/><xsl:text>_ </xsl:text>
    <xsl:text>*</xsl:text><xsl:value-of select="@odl:name"/><xsl:text>*</xsl:text>
    <xsl:call-template name="method-signature"/>
    <xsl:text>\\
</xsl:text>
    <xsl:call-template name="description"/>
    <xsl:if test="odl:argument">
      <xsl:for-each select="odl:argument">
        <xsl:text>\\
</xsl:text>
        <xsl:text>*</xsl:text><xsl:value-of select="@odl:name"/><xsl:text>*: </xsl:text>
        <xsl:value-of select="normalize-space(odl:description)"/>
      </xsl:for-each>
    </xsl:if>
    <xsl:text>\\
</xsl:text>
    <xsl:text>*</xsl:text>returns<xsl:text>*: </xsl:text><xsl:value-of select="normalize-space(odl:return/odl:description)"/>
    <xsl:if test="odl:error/odl:description">
      <xsl:text>\\
</xsl:text>
      <xsl:text>*</xsl:text>error<xsl:text>*: </xsl:text><xsl:value-of select="normalize-space(odl:error/odl:description)"/>
    </xsl:if>
    <xsl:text> | </xsl:text>
     <xsl:choose>
      <xsl:when test="odl:deprecated">
        <xsl:text>DEPRECATED</xsl:text>
      </xsl:when>
      <xsl:otherwise>
        <xsl:text> -- </xsl:text>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> | -- | </xsl:text>
    <xsl:choose>
      <xsl:when test="odl:version/odl:description">
        <xsl:value-of select="normalize-space(odl:version/odl:description)"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$version"/>
      </xsl:otherwise>
    </xsl:choose>
    <xsl:text> |&#10;</xsl:text>
  </xsl:template>

  <xsl:template name="method-signature">
    <xsl:text>(</xsl:text>
    <xsl:for-each select="odl:argument">
      <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
      <xsl:text>_</xsl:text>
      <xsl:if test="@odl:out"><xsl:text>out </xsl:text></xsl:if>
      <xsl:if test="@odl:in"><xsl:text>in </xsl:text></xsl:if>
      <xsl:value-of select="@odl:type"/>
      <xsl:text>_</xsl:text>
      <xsl:text> </xsl:text>
      <xsl:value-of select="@odl:name"/>
    </xsl:for-each>
    <xsl:text>)</xsl:text>
  </xsl:template>

  <xsl:template name="bbf-path">
    <xsl:choose>
      <xsl:when test="@odl:instance">
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path-instance"/>
          </xsl:for-each>
          <xsl:text>.</xsl:text>
        </xsl:if>
        <xsl:value-of select="concat('\{', @odl:name, '\}')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path"/>
          </xsl:for-each>
          <xsl:text>.</xsl:text>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="@odl:template">
            <xsl:value-of select="concat(@odl:name, '.\{i\}')"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="@odl:name"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="bbf-path-instance">
    <xsl:choose>
      <xsl:when test="@odl:instance">
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path-instance"/>
          </xsl:for-each>
          <xsl:text>.</xsl:text>
        </xsl:if>
        <xsl:value-of select="concat('\{', @odl:name, '\}')"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path"/>
          </xsl:for-each>
          <xsl:text>.</xsl:text>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="@odl:template">
            <xsl:value-of select="@odl:name"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="@odl:name"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="description">
    <xsl:value-of select="normalize-space(odl:description/*[1])"/>
  </xsl:template>

  <xsl:template match="odl:type">
     <xsl:text>h2. </xsl:text><xsl:value-of select="@odl:name"/><xsl:text>
</xsl:text>
     <xsl:call-template name="description"/><xsl:text>

</xsl:text>
     <xsl:apply-templates select="odl:member"/>
     <xsl:text>
</xsl:text>
  </xsl:template>

  <xsl:template match="odl:member">
    <xsl:text>* _</xsl:text>
    <xsl:value-of select="@odl:type"/><xsl:text>_ *</xsl:text><xsl:value-of select="@odl:name"/>
    <xsl:text>*:</xsl:text>
     <xsl:call-template name="description"/>
     <xsl:text>
</xsl:text>
  </xsl:template>
</xsl:stylesheet>
