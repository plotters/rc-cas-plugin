# Requirements #
  * phpCAS 1.0.1+: visit http://www.ja-sig.org/wiki/display/CASC/phpCAS for details and installation instructions.


# Installation #
See http://trac.roundcube.net/wiki/Doc_Plugins#InstallingandactivatingPlugins for instructions on installing RoundCube plugins.


# Configuration #
The config.inc.php.dist file contains the configuration settings for the plugin. These settings need to be changed to match those of your CAS server and IMAP backend. This file needs to be renamed config.inc.php after the necessary changes are made.

## These changes are necessary ##
  * cas\_proxy: specifies whether RoundCube is acting as a CAS proxy for the IMAP backend. If set to true, cas\_imap\_name must also be specified. If set to false, cas\_imap\_password must also be specified.
  * cas\_hostname: specifies the host name of the CAS server, e.g. www.my-cas-server.com.
  * cas\_validation: specifies SSL validation of the CAS server. If set to "ca" or "self", cas\_cert must also be specified.

## These changes are optional ##
  * cas\_imap\_caching: specifies whether the IMAP backend caches authentication credentials. This setting should accurately reflect how the IMAP backend is configured for optimal performance.
  * cas\_port: this is typically 443.
  * cas\_uri
  * cas\_login\_url
  * cas\_logout\_url