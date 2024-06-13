<?xml version="1.0"?>

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:odl="http://www.softathome.com/odl"
                xmlns="http://www.w3.org/1999/xhtml"
                xmlns:str="http://exslt.org/strings"
                extension-element-prefixes="str"
                exclude-result-prefixes="odl">

  <xsl:output method="xml" encoding="string" omit-xml-declaration="yes" indent="yes"/>

  <xsl:template match="/">
    <xsl:call-template name="toc"/>
    <xsl:call-template name="alltypes"/>
    <xsl:call-template name="files"/>
    <xsl:call-template name="webservices"/>
    <xsl:apply-templates select="//odl:object"/>
  </xsl:template>

  <xsl:template name="toc">
    <html lang="en">
      <xsl:call-template name="head"/>
      <body>
        <xsl:call-template name="header"/>
        <div id="parent">
          <div id="pane">
            <xsl:call-template name="index"/>
            <div class="content">
              <h1 class="classTitle">Objects Index</h1>
                <xsl:for-each select="/odl:datamodel-set/odl:datamodel/odl:object[not(@odl:mib)]">
                  <xsl:sort select="@odl:path"/>
                  <div class="index-class">
                    <h3>
                      <a>
                        <xsl:attribute name="href"><xsl:value-of select="concat(@odl:path, '.html')"/></xsl:attribute>
                        <xsl:value-of select="@odl:name"/>
                      </a>
                    </h3>
                    <div class="description">
                      <xsl:call-template name="description"/><xsl:text> </xsl:text>
                    </div>
                  </div>
                  <hr></hr>
                </xsl:for-each>
              <h1 class="classTitle">Types Index</h1>
                <xsl:for-each select="/odl:datamodel-set/odl:types/odl:type">
                  <xsl:sort select="@odl:name"/>
                  <div class="index-class">
                    <h3>
                      <a>
                        <xsl:attribute name="href"><xsl:value-of select="concat('types.html', @odl:name)"/></xsl:attribute>
                        <xsl:value-of select="@odl:name"/>
                      </a>
                    </h3>
                    <div class="description">
                      <xsl:call-template name="description"/><xsl:text> </xsl:text>
                    </div>
                  </div>
                  <hr></hr>
                </xsl:for-each>
            </div>
          </div>
        </div>
        <xsl:call-template name="fineprint"/>
      </body>
    </html>
  </xsl:template>

  <xsl:template name="index">
    <div class="nav">
      <li class="menuparent">
        <a href="index.html">OBJECTS</a>
        <xsl:if test="/odl:datamodel-set/odl:datamodel/odl:object[not(@odl:mib)]">
          <ul class="sub-menu">
            <xsl:for-each select="/odl:datamodel-set/odl:datamodel/odl:object[not(@odl:mib)]">
              <xsl:sort select="@odl:path"/>
              <xsl:call-template name="menu"/>
            </xsl:for-each>
          </ul>
        </xsl:if>
      </li>
      <li class="menuparent">
        <a href="types.html">TYPES</a>
        <xsl:if test="/odl:datamodel-set/odl:types/odl:type">
          <ul class="sub-menu">
            <xsl:for-each select="/odl:datamodel-set/odl:types/odl:type">
            <xsl:sort select="@odl:name"/>
              <xsl:call-template name="menu-type"/>
            </xsl:for-each>
          </ul>
        </xsl:if>
      </li>
      <li class="menuparent">
        <a href="webservices.html">APIs</a>
        <xsl:if test="/odl:datamodel-set/odl:datamodel/odl:object[not(@odl:mib)]">
          <ul class="sub-menu">
            <xsl:for-each select="/odl:datamodel-set/odl:datamodel/odl:object[not(@odl:mib)]">
            <xsl:sort select="@odl:path"/>
              <xsl:if test="count(odl:function/odl:acl/odl:execute/odl:group[@odl:name!='cwmpd'])>0">
                <li class="menuparent">
                  <a>
                    <xsl:attribute name="href"><xsl:value-of select="concat('webservices.html#', @odl:path)"/></xsl:attribute>
                    <xsl:value-of select="@odl:name"/>
                  </a>
                  <ul class="sub-menu">
                    <xsl:call-template name="menu-ws"/>
                  </ul>
                </li>
              </xsl:if>
            </xsl:for-each>
          </ul>
        </xsl:if>
      </li>
    </div>
  </xsl:template>

  <xsl:template name="alltypes">
    <xsl:variable name="current-output"><xsl:value-of select="concat($output, '/types.html')"/></xsl:variable>
    <xsl:document href="{$current-output}">
      <html lang="en">
        <xsl:call-template name="head"/>
        <body>
          <xsl:call-template name="header"/>
          <div id="parent">
            <div id="pane">
              <xsl:call-template name="index"/>
              <div class="content">
                <h1 class="classTitle">Types Index</h1>
                <xsl:for-each select="/odl:datamodel-set/odl:types/odl:type">
                  <xsl:sort select="@odl:name"/>
                  <div class="index-class">
                    <h3>
                      <a>
                        <xsl:attribute name="href"><xsl:value-of select="concat('types.html', @odl:name)"/></xsl:attribute>
                        <xsl:value-of select="@odl:name"/>
                      </a>
                    </h3>
                    <xsl:if test="odl:description">
                    <div class="description">
                      <xsl:call-template name="description"/>
                    </div>
                    </xsl:if>
                    <p class="version">
                      <xsl:choose>
                        <xsl:when test="odl:version-description">
                          <br />Version  <xsl:value-of select="odl:version-description"/><br />
                        </xsl:when>
                        <xsl:when test="$version">
                          <br />Version  <xsl:value-of select="$version"/><br />
                        </xsl:when>
                      </xsl:choose>
                      <xsl:call-template name="defined"/>
                    </p>

                    <xsl:if test="odl:member">
                      <div class="block">
                        <table class="summaryTable" cellspacing="0">
                          <xsl:attribute name="summary">
                            A summary of the members documented in the type <xsl:value-of select="@odl:name"/>
                          </xsl:attribute>

                          <caption>Members</caption>
                          <thead>
                            <tr>
                              <th scope="col">Member Type</th>
                              <th scope="col">Member Name and Description</th>
                            </tr>
                          </thead>
                          <tbody>
                            <xsl:for-each select="odl:member">
                              <tr>
                                <td class="attributes">
                                  <div class="fixedFont parameterType">
                                    <xsl:value-of select="@odl:type"/>
                                  </div>
                                </td>
                                <td class="nameDescription">
                                  <div class="fixedFont">
                                    <b>
                                      <xsl:value-of select="@odl:name"/>
                                    </b>
                                  </div>

                                  <div class="description">
                                    <xsl:call-template name="description"/>
                                  </div>
                                </td>
                              </tr>
                            </xsl:for-each>
                          </tbody>
                        </table>
                      </div>
                    </xsl:if>
                  </div>
                  <hr></hr>
                </xsl:for-each>
              </div>
            </div>
          </div>
          <xsl:call-template name="fineprint"/>
        </body>
      </html>
    </xsl:document>
  </xsl:template>

  <xsl:template match="odl:type">
    <a>
      <xsl:attribute name="name"><xsl:value-of select="@odl:name"/></xsl:attribute>
      <xsl:value-of select="' '"/>
    </a>

    <h1 class="classTitle">
      <xsl:value-of select="@odl:name"/>
    </h1>


  </xsl:template>

  <xsl:template match="odl:object">
    <xsl:variable name="current-output"><xsl:value-of select="concat($output, '/', @odl:path, '.html')"/></xsl:variable>
    <xsl:document href="{$current-output}">
      <html lang="en">
        <xsl:call-template name="head"/>
        <body>
          <xsl:call-template name="header"/>
          <div id="parent">
            <div id="pane">
              <xsl:call-template name="index"/>
              <div class="content">
                <xsl:call-template name="object"/>
              </div>
            </div>
          </div>
          <xsl:call-template name="fineprint"/>
        </body>
      </html>
    </xsl:document>
  </xsl:template>

  <xsl:template name="head">
    <head>
      <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
      <title><xsl:value-of select="$title"/></title>
      <link href="style.css" rel="stylesheet" type="text/css" />
    </head>
  </xsl:template>

  <xsl:template name="header">
    <div id="myHeader">
      <div id="myTitle">
        <h2><xsl:value-of select="$title"/></h2>
      </div>
      <div id="mySubTitle">
        <h1><xsl:value-of select="$subtitle"/></h1>
      </div>
      <div id="myLinks">
        <a href="index.html">datamodel</a> |
        <a href="types.html">types</a> |
        <a href="files.html">files</a>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="fineprint">
    <div class="fineprint" style="clear:both">&#169; Copyrights SoftAtHome 2018</div>
  </xsl:template>

  <xsl:template name="menu">
    <li class="menuparent">
      <a>
        <xsl:attribute name="href"><xsl:value-of select="concat(@odl:path, '.html')"/></xsl:attribute>
        <xsl:value-of select="@odl:name"/>
      </a>
      <xsl:if test="odl:object">
        <ul class="sub-menu">
          <xsl:for-each select="odl:object">
            <xsl:sort select="@odl:path"/>
            <xsl:call-template name="menu"/>
          </xsl:for-each>
        </ul>
      </xsl:if>
    </li>
  </xsl:template>

  <xsl:template name="menu-type">
    <li>
      <a>
        <xsl:attribute name="href"><xsl:value-of select="concat('types.html#', @odl:name)"/></xsl:attribute>
        <xsl:value-of select="@odl:name"/>
      </a>
    </li>
  </xsl:template>

  <xsl:template name="menu-ws">
    <xsl:if test="odl:object">
      <xsl:for-each select="odl:object">
        <xsl:sort select="@odl:name"/>
        <li class="menuparent">
          <xsl:if test="count(odl:function/odl:acl/odl:execute/odl:group[@odl:name!='cwmpd'])>0">
            <a>
              <xsl:attribute name="href"><xsl:value-of select="concat('webservices.html#', ../@odl:path, '.', @odl:name)"/></xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
            <xsl:if test="odl:object">
              <ul class="sub-menu">
                <xsl:call-template name="menu-ws"/>
              </ul>
            </xsl:if>
            <xsl:if test="odl:function">
              <ul class="sub-menu">
                <xsl:call-template name="menu-ws"/>
              </ul>
            </xsl:if>
          </xsl:if>
        </li>
      </xsl:for-each>
      <hr></hr>
    </xsl:if>
    <xsl:if test="odl:function">
      <li class="menuparent">
        <xsl:for-each select="odl:function">
          <xsl:sort select="@odl:name"/>
          <xsl:if test="count(odl:acl/odl:execute/odl:group[@odl:name!='cwmpd'])>0">
            <a>
              <xsl:attribute name="href"><xsl:value-of select="concat('webservices.html#', ../@odl:path, '.', @odl:name)"/></xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
          </xsl:if>
        </xsl:for-each>
      </li>
    </xsl:if>
  </xsl:template>

  <xsl:template name="object">
    <a>
      <xsl:attribute name="name">object[<xsl:value-of select="@odl:path"/>]</xsl:attribute>
      <xsl:value-of select="' '"/>
    </a>

    <h1 class="classTitle">
      <xsl:choose>
        <xsl:when test="@odl:mib">
          <i><xsl:call-template name="bbf-path"/></i>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="bbf-path"/>
        </xsl:otherwise>
      </xsl:choose>
    </h1>

    <div class="objAttributes">

      <xsl:choose>
        <xsl:when test="@odl:persistent">
          <div class="objPersistent">
            <p><img src="check.png"/>PERSISTENT</p>
          </div>
        </xsl:when>
        <xsl:otherwise>
          <div class="objPersistent">
            <p><img src="cross.png"/>PERSISTENT</p>
          </div>
        </xsl:otherwise>
      </xsl:choose>

      <xsl:choose>
        <xsl:when test="@odl:read-only">
          <div class="objR-O">
            <p><img src="check.png"/>READ ONLY</p>
          </div>
        </xsl:when>
        <xsl:otherwise>
          <div class="objR-O">
            <p><img src="cross.png"/>READ ONLY</p>
          </div>
        </xsl:otherwise>
      </xsl:choose>

      <xsl:choose>
        <xsl:when test="@odl:template">
          <div class="objTemplate">
            <p><img src="check.png"/>MULTI INSTANCES</p>
          </div>
          <xsl:if test="odl:counter">
            <div class="objCounter">
              <p>Counter : <xsl:value-of select="odl:object/@odl:counter"/></p>
            </div>
          </xsl:if>
        </xsl:when>
        <xsl:when test="@odl:instance">
          <div class="objTemplate">
            <p><img src="check.png"/>INSTANCE</p>
          </div>
        </xsl:when>
        <xsl:otherwise>
          <div class="objTemplate">
            <p><img src="cross.png"/>MULTI INSTANCES</p>
          </div>
        </xsl:otherwise>
      </xsl:choose>

    </div>

    <ul>
      <xsl:for-each select="child::odl:object">
        <li>
          <a>
            <xsl:attribute name="href"><xsl:value-of select="concat(@odl:path, '.html')"/></xsl:attribute>
            <xsl:value-of select="@odl:name"/>
          </a>
        </li>
      </xsl:for-each>
    </ul>

    <xsl:if test="odl:description">
      <div class="description">
        <xsl:call-template name="description"/>
      </div>
    </xsl:if>

    <xsl:if test="odl:add-description or odl:delete-description or odl:updated-description or odl:extend-with">
      <dl>
        <xsl:if test="odl:add-description">
          <dt>when added,</dt>
          <dd><xsl:value-of select="odl:add-description"/></dd>
        </xsl:if>
        <xsl:if test="odl:delete-description">
          <dt>when deleted,</dt>
          <dd><xsl:value-of select="odl:delete-description"/></dd>
        </xsl:if>
        <xsl:if test="odl:update-description">
          <dt>when updated,</dt>
          <dd><xsl:value-of select="odl:update-description"/></dd>
        </xsl:if>
        <xsl:if test="odl:extend-with">
          <dt>extended with</dt>
          <dd>
            <xsl:for-each select="odl:extend-with">
              <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
              <a>
                <xsl:attribute name="href"><xsl:value-of select="concat(., '.html')"/></xsl:attribute>
                <xsl:value-of select="."/>
              </a>
            </xsl:for-each>
          </dd>
        </xsl:if>
      </dl>
    </xsl:if>

    <xsl:call-template name="acls"/>

    <xsl:if test="@odl:counter">
      <p class="counted">
        <xsl:text>Counted with </xsl:text>
        <b>
          <a class="fixedFont">
            <xsl:attribute name="href"><xsl:value-of select="concat(../@odl:path, '.html#parameter[', ../@odl:path, '#', @odl:counter)"/>]</xsl:attribute>
            <xsl:value-of select="@odl:counter"/>
          </a>
        </b>
      </p>
    </xsl:if>

    <p class="version">
      <xsl:choose>
        <xsl:when test="odl:version-description">
          <br />Version  <xsl:value-of select="odl:version-description"/><br />
        </xsl:when>
        <xsl:when test="$version">
          <br />Version  <xsl:value-of select="$version"/><br />
        </xsl:when>
      </xsl:choose>
      <xsl:call-template name="defined"/>
    </p>

    <xsl:if test="odl:parameter">
      <div class="block">
        <table class="summaryTable" cellspacing="0">
          <xsl:attribute name="summary">
            A summary of the parameters documented in the object <xsl:value-of select="@odl:name"/>
          </xsl:attribute>

          <caption>Parameter Summary</caption>
          <thead>
            <tr>
              <th scope="col">Parameter Attributes</th>
              <th scope="col">Parameter Name and Description</th>
            </tr>
          </thead>
          <tbody>
            <xsl:for-each select="odl:parameter">
              <tr>
                <td class="attributes">
                  <div class="fixedFont parameterType">
                    <xsl:value-of select="@odl:type"/>
                  </div>
                  &#160;
                  <xsl:call-template name="parameter-attributes"/>
                </td>
                <td class="nameDescription">
                  <div class="fixedFont">
                    <b>
                      <a>
                        <xsl:attribute name="href">#parameter[<xsl:value-of select="concat(../@odl:path, '#', @odl:name)"/>]</xsl:attribute>
                        <xsl:value-of select="@odl:name"/>
                      </a>
                    </b>
                    <xsl:if test="odl:default">
                      <span class="default">
                        <xsl:text> = </xsl:text>
                        <span class="value"><xsl:value-of select="odl:default"/></span>
                      </span>
                    </xsl:if>
                  </div>
                  <div class="briefDescription">
                    <xsl:call-template name="brief-description"/>
                  </div>
                </td>
              </tr>
            </xsl:for-each>
          </tbody>
        </table>
      </div>
    </xsl:if>

    <xsl:if test="odl:function">
      <div class="block">
        <table class="summaryTable" cellspacing="0">
          <xsl:attribute name="summary">
            A summary of the methods documented in the object <xsl:value-of select="@odl:name"/>
          </xsl:attribute>

          <caption>Method Summary</caption>
          <thead>
            <tr>
              <th scope="col">Method Attributes</th>
              <th scope="col">Method Name and Description</th>
            </tr>
          </thead>
          <tbody>
            <xsl:for-each select="odl:function">
              <tr>
                <td class="attributes">
                  <div class="fixedFont returnType">
                    <xsl:apply-templates select="odl:return"/>
                  </div>
                  &#160;
                  <xsl:call-template name="function-attributes"/>
                </td>
                <td class="nameDescription">
                  <div class="fixedFont">
                    <b>
                      <a>
                        <xsl:attribute name="href">#function[<xsl:value-of select="concat(../@odl:path, '#', @odl:name)"/>]</xsl:attribute>
                        <xsl:value-of select="@odl:name"/>
                      </a>
                    </b>
                    <xsl:call-template name="method-signature"/>
                  </div>
                  <div class="briefDescription">
                    <xsl:call-template name="brief-description"/>
                  </div>
                </td>
              </tr>
            </xsl:for-each>
          </tbody>
        </table>
      </div>
    </xsl:if>

    <xsl:if test="odl:parameter">
      <div class="sectionTitle">
        Parameter Details
      </div>
      <xsl:apply-templates select="odl:parameter"/>
    </xsl:if>

    <xsl:if test="odl:function">
      <div class="sectionTitle">
        Method Details
      </div>
      <xsl:apply-templates select="odl:function"/>
    </xsl:if>
  </xsl:template>

  <xsl:template match="odl:parameter">
    <xsl:if test="position() > 1"><hr></hr></xsl:if>
    <div class="parameter">
      <a>
        <xsl:attribute name="name">parameter[<xsl:value-of select="concat(../@odl:path, '#', @odl:name)"/>]</xsl:attribute>
        <xsl:text> </xsl:text>
      </a>
      <div class="fixedFont">
        <span class="parameterType"><xsl:value-of select="@odl:type"/></span>
        <xsl:text> </xsl:text>
        <b><xsl:value-of select="@odl:name"/></b>
        <xsl:if test="odl:default">
          <span class="default"><xsl:text> = </xsl:text><span class="value"><xsl:value-of select="odl:default"/></span></span>
        </xsl:if>
      </div>

      <xsl:if test="@odl:read-only|@odl:persistent|@odl:volatile|@odl:instance-counter">
        <div class="attributes">
          <xsl:call-template name="parameter-attributes"/>
        </div>
      </xsl:if>

      <xsl:if test="@odl:instance-counter">
        <p class="counter">
          <xsl:text>Instance counter for </xsl:text>
          <b>
            <a class="fixedFont">
              <xsl:attribute name="href"><xsl:value-of select="concat(../@odl:path, '.', @odl:counted-object, '.html')"/></xsl:attribute>
              <xsl:value-of select="@odl:counted-object"/>
            </a>
          </b>
        </p>
      </xsl:if>

      <div class="description">
        <xsl:call-template name="description"/>
      </div>
      <xsl:if test="odl:updated-description">
        <dl>
          <xsl:if test="odl:update-description">
            <dt>when updated,</dt>
            <dd><xsl:value-of select="odl:update-description"/></dd>
          </xsl:if>
        </dl>
      </xsl:if>
      <xsl:if test="odl:version-description">
        Since version: <xsl:value-of select="odl:version-description"/>
      </xsl:if>

      <xsl:if test="odl:validator">
        <h4>constraints</h4>
        <xsl:apply-templates select="odl:validator"/>
      </xsl:if>

      <xsl:call-template name="acls"/>
      <xsl:call-template name="defined"/>
    </div>
  </xsl:template>

  <xsl:template match="odl:function">
    <xsl:if test="position() > 1"><hr></hr></xsl:if>
    <div class="function">
      <div class="methodDetail">
        <a>
          <xsl:attribute name="name">function[<xsl:value-of select="concat(../@odl:path, '#', @odl:name)"/>]</xsl:attribute>
          <xsl:text> </xsl:text>
        </a>
        <xsl:value-of select="@odl:name"/>
      </div>
      <div class="fixedFont">
      <xsl:if test="odl:deprecated">
        <span class="argAttributes">
          &#60;deprecated&#62;<xsl:text> </xsl:text>
        </span>
      </xsl:if>
        <span class="returnType">
          <xsl:apply-templates select="odl:return"/>
        </span>
        <xsl:text> </xsl:text>
        <b><xsl:value-of select="@odl:name"/></b>
        <xsl:call-template name="method-signature"/>
      </div>
      <xsl:if test="@odl:message|@odl:template-only">
        <div class="attributes">
          <xsl:call-template name="function-attributes"/>
          <xsl:text> </xsl:text>
        </div>
      </xsl:if>
      <div class="description">
        <xsl:call-template name="description"/><xsl:text> </xsl:text>
      </div>
      <dl class="methodArguments">
        <xsl:if test="odl:argument">
          <xsl:apply-templates select="odl:argument"/>
        </xsl:if>
        <xsl:text> </xsl:text>
      </dl>
      <div class="retErr">
        <p>Returns : <span class="returnType">  <xsl:value-of select="odl:return/@odl:type"/></span></p><xsl:text> </xsl:text>
      </div>
      <xsl:if test="odl:error/odl:description">
        <div class="retErr">
          <p>Error</p><xsl:value-of select="odl:error/odl:description"/>
        </div>
      </xsl:if>
     </div>
  </xsl:template>

  <xsl:template match="odl:argument">
    <dt class="argumentDesc">
      <xsl:if test="@odl:mandatory">
        <span class="argAttributes">&#60;mandatory&#62;</span>
        <xsl:text> </xsl:text>
      </xsl:if>
      <span class="argumentType"><xsl:call-template name="type"/></span>
      <xsl:text> </xsl:text>
      <span class="argumentName"><xsl:value-of select="@odl:name"/></span>
    </dt>
    <dd>
      <xsl:apply-templates select="odl:description"/>
    </dd>
  </xsl:template>

  <xsl:template name="WS-call">
    <xsl:for-each select="odl:argument">
      <ul class="argumentName">"<xsl:value-of select="@odl:name"/>"<xsl:text> : </xsl:text>
      <xsl:choose>
        <xsl:when test="@odl:type = 'variant'">
          {<span class="argumentType"><xsl:value-of select="@odl:type"/></span>},
        </xsl:when>
        <xsl:when test="@odl:type = 'list'">
          [<span class="argumentType"><xsl:value-of select="@odl:type"/></span>],
        </xsl:when>
        <xsl:when test="(@odl:type = 'string') or (@odl:type = 'int8') or (@odl:type = 'int16') or (@odl:type = 'int32') or (@odl:type = 'int64') or (@odl:type = 'uint8') or (@odl:type = 'uint16') or (@odl:type = 'uint32') or (@odl:type = 'uint64') or (@odl:type = 'bool')">
          "<span class="argumentType"><xsl:value-of select="@odl:type"/></span>",
        </xsl:when>
        <xsl:otherwise>
          {<span class="argumentType"><xsl:value-of select="@odl:type"/></span>},
        </xsl:otherwise>
      </xsl:choose>
      </ul>
    </xsl:for-each>
  </xsl:template>

  <xsl:template match="odl:return">
    <xsl:call-template name="type"/>
  </xsl:template>

  <xsl:template name="arg-call">
    <xsl:for-each select="odl:argument">
      <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
      <xsl:value-of select="@odl:name"/>:<span class="argumentType"><xsl:value-of select="@odl:type"/></span>
        <xsl:if test="@odl:mandatory">
          <span class="argAttributes"> &#60;mandatory&#62;</span>
          <xsl:text> </xsl:text>
        </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="bbf-call">
    <xsl:choose>
      <xsl:when test="@odl:instance">
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path-instance"/>
          </xsl:for-each>
          <xsl:text>.</xsl:text>
        </xsl:if>
        <xsl:value-of select="'{'"/>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html')"/>
          </xsl:attribute>
          <xsl:value-of select="@odl:name"/>
        <xsl:value-of select="'}'"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:if test="parent::odl:object">
          <xsl:for-each select="parent::odl:object">
            <xsl:call-template name="bbf-path"/>
          </xsl:for-each>
        </xsl:if>
        <xsl:choose>
          <xsl:when test="@odl:template">
              <xsl:attribute name="href">
                <xsl:value-of select="concat(@odl:path, '.html')"/>
              </xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            <xsl:value-of select="'.{i}'"/>
          </xsl:when>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="type">
    <xsl:variable name="type" select="@odl:type"/>
    <xsl:choose>
      <xsl:when test="//odl:type[@odl:name=$type]">
        <a>
          <xsl:attribute name="class">link type tooltip</xsl:attribute>
          <xsl:attribute name="href">
            <xsl:value-of select="concat('types.html#', @odl:type)"/>
          </xsl:attribute>
          <xsl:value-of select="@odl:type"/>
          <span class="type-define">
            <table class="summaryTable" cellspacing="0">
              <caption><xsl:value-of select="@odl:type"/></caption>
              <thead>
                <tr>
                  <th scope="col">Member Type</th>
                  <th scope="col">Member Name</th>
                </tr>
              </thead>
              <tbody>
                <xsl:for-each select="//odl:type[@odl:name=$type]/odl:member">
                  <tr>
                    <td class="memberType"><xsl:value-of select="@odl:type"/></td>
                    <td><xsl:value-of select="@odl:name"/></td>
                  </tr>
                </xsl:for-each>
              </tbody>
            </table>
          </span>
        </a>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="@odl:type"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='enum']">
    <p>
      Value must be one of
      <xsl:for-each select="odl:value">
        <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
        <xsl:value-of select="."/>
      </xsl:for-each>
    </p>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='range']">
    <div class="fixedFont">
      <xsl:value-of select="@odl:min"/>
      <xsl:text> &#60; value &#60; </xsl:text>
      <xsl:value-of select="@odl:max"/>
    </div>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='minimum']">
    <div class="fixedFont">
      <xsl:value-of select="@odl:min"/>
      <xsl:text> &#60; value </xsl:text>
    </div>
  </xsl:template>

  <xsl:template match="odl:validator[@odl:type='maximum']">
    <div class="fixedFont">
      <xsl:text>value &#60; </xsl:text>
      <xsl:value-of select="@odl:max"/>
    </div>
  </xsl:template>

  <xsl:template name="brief-description">
    <xsl:apply-templates select="odl:description/*[1]/node()" mode="identity"/>
  </xsl:template>

  <xsl:template name="description">
    <xsl:apply-templates select="odl:description/*" mode="identity"/>
  </xsl:template>

  <xsl:template name="parameter-attributes">
    <xsl:if test="@odl:read-only">&#60;read-only&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:persistent">&#60;persistent&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:volatile">&#60;volatile&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:counter">&#60;instance-counter&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:key">&#60;key&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:unique">&#60;unique&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:private">&#60;private&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:proteccted">&#60;protected&#62;<xsl:text> </xsl:text></xsl:if>
  </xsl:template>

  <xsl:template name="function-attributes">
    <xsl:if test="@odl:message">&#60;message&#62;<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:template-only">&#60;template-only&#62;<xsl:text> </xsl:text></xsl:if>
  </xsl:template>

  <xsl:template name="argument-attributes">
    <xsl:if test="@odl:in">in<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:out">out<xsl:text> </xsl:text></xsl:if>
    <xsl:if test="@odl:mandatory">&#60;mandatory&#62;<xsl:text> </xsl:text></xsl:if>
  </xsl:template>

  <xsl:template name="method-signature">
    <xsl:text>(</xsl:text>
    <xsl:for-each select="odl:argument">
      <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
      <xsl:if test="@odl:in|@odl:out|@odl:mandatory">
        <span class="argAttributes"> <xsl:call-template name="argument-attributes"/></span>
      </xsl:if>
      <span class="argumentType"><xsl:call-template name="type"/></span>
      <xsl:text> </xsl:text>
      <span class="argumentName"><xsl:value-of select="@odl:name"/></span>
    </xsl:for-each>
    <xsl:text>)</xsl:text>
  </xsl:template>

  <xsl:template name="identity" match="@*|node()" mode="identity">
    <xsl:choose>
      <xsl:when test="name() = 'odl:link'">
        <xsl:call-template name="link"/>
      </xsl:when>
      <xsl:otherwise>
        <xsl:copy>
          <xsl:apply-templates select="@*|node()" mode="identity"/>
        </xsl:copy>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="odl:link" name="link">
    <a>
      <xsl:choose>
        <xsl:when test="@odl:type = 'object'">
          <xsl:attribute name="class">link object<xsl:if test="@odl:unresolved"> unresolved</xsl:if></xsl:attribute>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html')"/>
          </xsl:attribute>
        </xsl:when>
        <xsl:when test="@odl:type = 'parameter'">
          <xsl:attribute name="class">link parameter<xsl:if test="@odl:unresolved"> unresolved</xsl:if></xsl:attribute>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html#parameter[', @odl:path, '#', @odl:member, ']')"/>
          </xsl:attribute>
        </xsl:when>
        <xsl:when test="@odl:type = 'function'">
          <xsl:attribute name="class">link function<xsl:if test="@odl:unresolved"> unresolved</xsl:if></xsl:attribute>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html#function[', @odl:path, '#', @odl:member, ']')"/>
          </xsl:attribute>
        </xsl:when>
        <xsl:when test="@odl:type = 'type'">
          <xsl:attribute name="class">link type<xsl:if test="@odl:unresolved"> unresolved</xsl:if></xsl:attribute>
          <xsl:attribute name="href">
            <xsl:value-of select="concat('types.html#', @odl:path)"/>
          </xsl:attribute>
        </xsl:when>
      </xsl:choose>
      <xsl:value-of select="."/>
      <xsl:if test="@odl:type = 'function'"><xsl:text>()</xsl:text></xsl:if>
    </a>
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
        <xsl:value-of select="'{'"/>
        <a>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html')"/>
          </xsl:attribute>
          <xsl:value-of select="@odl:name"/>
        </a>
        <xsl:value-of select="'}'"/>
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
            <a>
              <xsl:attribute name="href">
                <xsl:value-of select="concat(@odl:path, '.html')"/>
              </xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
            <xsl:value-of select="'.{i}'"/>
          </xsl:when>
          <xsl:otherwise>
            <a>
              <xsl:attribute name="href">
                <xsl:value-of select="concat(@odl:path, '.html')"/>
              </xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
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
        <xsl:value-of select="'{'"/>
        <a>
          <xsl:attribute name="href">
            <xsl:value-of select="concat(@odl:path, '.html')"/>
          </xsl:attribute>
          <xsl:value-of select="@odl:name"/>
        </a>
        <xsl:value-of select="'}'"/>
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
            <a>
              <xsl:attribute name="href">
                <xsl:value-of select="concat(@odl:path, '.html')"/>
              </xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
          </xsl:when>
          <xsl:otherwise>
            <a>
              <xsl:attribute name="href">
                <xsl:value-of select="concat(@odl:path, '.html')"/>
              </xsl:attribute>
              <xsl:value-of select="@odl:name"/>
            </a>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="defined">
    <p class="defined-in">
      <div>Defined in: <xsl:apply-templates select="odl:defined"/></div>
      <xsl:if test="odl:assigned">
        <div>Assigned in: <xsl:apply-templates select="odl:assigned"/></div>
      </xsl:if>
    </p>
  </xsl:template>

  <xsl:template match="odl:defined|odl:assigned">
    <a>
      <xsl:attribute name="class">file</xsl:attribute>
      <xsl:attribute name="href">
        <xsl:value-of select="concat('files.html#', @odl:file)"/>
      </xsl:attribute>
      <xsl:value-of select="@odl:file"/>
    </a>
    <xsl:text>:</xsl:text>
    <span class="line"><xsl:value-of select="@odl:line"/></span>
  </xsl:template>

  <xsl:template name="acls">
    <p class="acl">
      <div class="read">
        <xsl:choose>
          <xsl:when test="name(.) = 'odl:object'">
            Can browse:
          </xsl:when>
          <xsl:otherwise>
            Can read definition:
          </xsl:otherwise>
        </xsl:choose>
          <xsl:if test="not(odl:acl/odl:read/*)">
            <xsl:text>none</xsl:text>
          </xsl:if>
        <xsl:for-each select="odl:acl/odl:read/odl:user">
          <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
          <xsl:text>user </xsl:text><xsl:value-of select="@odl:name"/>
        </xsl:for-each>
        <xsl:text>  </xsl:text>
        <xsl:for-each select="odl:acl/odl:read/odl:group">
          <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
          <xsl:text>group </xsl:text><xsl:value-of select="@odl:name"/>
        </xsl:for-each>
      </div>
      <xsl:if test="name(.) != 'odl:function'">
        <div class="write">
          Can write:
          <xsl:if test="not(odl:acl/odl:write/*)">
            <xsl:text>none</xsl:text>
          </xsl:if>
          <xsl:for-each select="odl:acl/odl:write/odl:user">
            <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
            <xsl:text>user </xsl:text><xsl:value-of select="@odl:name"/>
          </xsl:for-each>
          <xsl:text>  </xsl:text>
          <xsl:for-each select="odl:acl/odl:write/odl:group">
            <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
            <xsl:text>group </xsl:text><xsl:value-of select="@odl:name"/>
          </xsl:for-each>
        </div>
      </xsl:if>
      <div class="execute">
        <xsl:choose>
          <xsl:when test="name(.) = 'odl:object'">
            Can execute functions:
          </xsl:when>
          <xsl:when test="name(.) = 'odl:parameter'">
            Can read value:
          </xsl:when>
          <xsl:otherwise>
            Can execute:
          </xsl:otherwise>
        </xsl:choose>
          <xsl:if test="not(odl:acl/odl:execute/*)">
            <xsl:text>none</xsl:text>
          </xsl:if>
        <xsl:for-each select="odl:acl/odl:execute/odl:user">
          <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
          <xsl:text>user </xsl:text><xsl:value-of select="@odl:name"/>
        </xsl:for-each>
        <xsl:text>  </xsl:text>
        <xsl:for-each select="odl:acl/odl:execute/odl:group">
          <xsl:if test="position() > 1"><xsl:text>, </xsl:text></xsl:if>
          <xsl:text>group </xsl:text><xsl:value-of select="@odl:name"/>
        </xsl:for-each>
      </div>
    </p>
  </xsl:template>

  <xsl:template name="ws">
    <dl class="methodArguments">
      <xsl:apply-templates select="odl:argument"/>
    </dl>
    <div class="wrapper">
      <div class="methodExample"><xsl:value-of select="@odl:name"/> - API</div>
      <div class="methodExTypeT">Interface</div>
      <div class="methodExCLI"><p>Command Line Interface</p></div>
      <div class="methodExWS"><p>WebService</p></div>
      <xsl:choose>
        <xsl:when test="odl:return/@odl:type='bool'">
          <div class="methodExReqT1">Request</div>
          <div class="methodExRespT">Response</div>

          <div class="methodCLIResp">
            <p>Expected CLI return : </p><xsl:call-template name="bbf-call"/>.<span class="method"><xsl:value-of select="@odl:name"/></span>() returns 1
          </div>
          <div class="methodWSResp">
            <p>Expected API return : </p>
            <pre>{'status': True}</pre>
          </div>
          <div class="methodCLIReq1">
            <p>
            <xsl:call-template name="bbf-call"/>.
            <span class="method">
            <xsl:value-of select="@odl:name"/>
            </span>
            (
            <xsl:call-template name="arg-call"/>
            ) :
            <span class="argumentwsT">
            <xsl:apply-templates select="odl:return"/>
            </span>
            </p>
          </div>
          <div class="methodWSReq1">
            <ul style="list-style: none;">
              <li>"service" : "<xsl:call-template name="bbf-call"/>",</li>
              <li>"method" : "<span class="method"><xsl:value-of select="@odl:name"/></span>",</li>
              <li>"parameters" : {<xsl:call-template name="WS-call"/></li>
              <ul>}</ul>
            </ul>
          </div>

        </xsl:when>
        <xsl:when test="odl:return/@odl:type='void'">
          <div class="methodExReqT1">Request</div>
          <div class="methodExRespT">Response</div>

          <div class="methodCLIResp">
            <p>Expected CLI return : </p><xsl:call-template name="bbf-call"/>.<span class="method"><xsl:value-of select="@odl:name"/></span>() done
          </div>
          <div class="methodWSResp">
            <p>Expected API return : </p>
            <pre>{'status': True}</pre>
          </div>
          <div class="methodCLIReq1">
            <p>
            <xsl:call-template name="bbf-call"/>.
            <span class="method">
            <xsl:value-of select="@odl:name"/>
            </span>
            (
            <xsl:call-template name="arg-call"/>
            ) :
            <span class="argumentwsT">
            <xsl:apply-templates select="odl:return"/>
            </span>
            </p>
          </div>
          <div class="methodWSReq1">
            <ul style="list-style: none;">
              <li>"service" : "<xsl:call-template name="bbf-call"/>",</li>
              <li>"method" : "<span class="method"><xsl:value-of select="@odl:name"/></span>",</li>
              <li>"parameters" : {<xsl:call-template name="WS-call"/></li>
              <ul>}</ul>
            </ul>
          </div>

        </xsl:when>
        <xsl:otherwise>

          <div class="methodExReqT">Request</div>
          <div class="methodCLIReq">
            <xsl:call-template name="bbf-call"/>.<span class="method"><xsl:value-of select="@odl:name"/></span>(<xsl:call-template name="arg-call"/>) :
            <span class="argumentwsT">
            <xsl:apply-templates select="odl:return"/>
            </span>
          </div>
          <div class="methodWSReq">
            <ul style="list-style: none;">
              <li>"service" : "<xsl:call-template name="bbf-call"/>",</li>
              <li>"method" : "<span class="method"><xsl:value-of select="@odl:name"/></span>",</li>
              <li>"parameters" : {<xsl:call-template name="WS-call"/></li>
              <ul>}</ul>
            </ul>
          </div>
        </xsl:otherwise>
      </xsl:choose>
      <div class="methodARC-VER">

        <xsl:if test="odl:deprecated">
          <p class="deprecated">
            Deprecated: <xsl:apply-templates select="odl:deprecated"/>
          </p>
        </xsl:if>

        <xsl:if test="odl:version/odl:description">
          <p>Since version: <xsl:value-of select="odl:version/odl:description"/></p>
        </xsl:if>

        <xsl:call-template name="acls"/>
        <xsl:call-template name="defined"/>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="files">
    <xsl:variable name="current-output"><xsl:value-of select="concat($output, '/files.html')"/></xsl:variable>
    <xsl:document href="{$current-output}">
      <html lang="en">
        <xsl:call-template name="head"/>
        <body>
          <xsl:call-template name="header"/>
          <div id="parent">
            <div id="pane">
              <xsl:call-template name="index"/>
              <div class="content">
                <h1 class="classTitle">File Locations</h1>
                <xsl:for-each select="//odl:location">
                  <xsl:sort select="@odl:file"/>
                  <div class="index-class">
                    <h3>
                      <a>
                        <xsl:attribute name="name"><xsl:value-of select="@odl:file"/></xsl:attribute>
                        <xsl:value-of select="' '"/>
                      </a>
                      <xsl:value-of select="@odl:file"/>
                    </h3>
                    <div class="description">
                      <dl>
                        <dt>Source path:</dt>
                        <dd><xsl:value-of select="."/></dd>
                        <dt>Component:</dt>
                        <dd><xsl:value-of select="@odl:component"/></dd>
                        <dt>Release:</dt>
                        <dd><xsl:value-of select="@odl:release"/></dd>
                      </dl>
                    </div>
                  </div>
                  <hr></hr>
                </xsl:for-each>
              </div>
            </div>
          </div>
          <xsl:call-template name="fineprint"/>
        </body>
      </html>
    </xsl:document>
  </xsl:template>

  <xsl:template name="webservices">
    <xsl:variable name="current-output"><xsl:value-of select="concat($output, '/webservices.html')"/></xsl:variable>
    <xsl:document href="{$current-output}">
      <html lang="en">
        <xsl:call-template name="head"/>
        <body>
          <xsl:call-template name="header"/>
          <div id="parent">
            <div id="pane">
              <xsl:call-template name="index"/>
              <div class="content">
                <h1 class="classTitle">APIs Index</h1>
                <xsl:for-each select="//odl:function">
                  <xsl:sort select="@odl:path"/>
                  <xsl:if test="count(odl:acl/odl:execute/odl:group[@odl:name!='cwmpd'])>0">
                    <div class="index-class">
                      <h3 id="{../@odl:path}.{@odl:name}">
                        <xsl:for-each select="parent::odl:object[not(@odl:mib)]">
                          <xsl:value-of select="@odl:path"/> /
                        </xsl:for-each>
                        <a><xsl:attribute name="href"><xsl:value-of select="concat('webservices.html#', ../@odl:path, '.', @odl:name)"/></xsl:attribute><xsl:value-of select="@odl:name"/></a>
                      </h3>
                      <xsl:call-template name="ws"/>
                    </div>
                    <hr></hr>
                  </xsl:if>
                </xsl:for-each>
              </div>
            </div>
          </div>
          <xsl:call-template name="fineprint"/>
        </body>
      </html>
    </xsl:document>
  </xsl:template>

</xsl:stylesheet>
