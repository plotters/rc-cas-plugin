<?php
/**
 * CAS Authentication
 *
 * This plugin replaces the Roundcube login page with authentication requests
 * to a CAS server, which enables logging into Roundcube with identities
 * authenticated by the CAS server and acts as a CAS proxy to relay authenticated
 * credentials to the IMAP backend.
 *
 * @version 0.4.1
 * @author Alex Li (li@hcs.harvard.edu)
 * 
 */

class cas_authentication extends rcube_plugin {

    /**
     * Initialize plugin
     *
     */
    function init() {
        // load plugin configurations
        $this->load_config();
        
        // add application hooks
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('render_page', array($this, 'render_page'));
        $this->add_hook('imap_connect', array($this, 'imap_connect'));
    }

    /**
     * Intercept startup actions
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function startup($args) {
        // retrieve rcmail instance
        $rcmail = rcmail::get_instance();
        
        // retrieve configurations
        $cfg = $rcmail->config->all();

        // intercept PGT callback action
        if ($args['action'] == 'pgtcallback') {
            // initialize CAS client
            $this->init_cas();
            
            // retrieve and store PGT if present
            phpCAS::forceAuthentication();
            
            // end script
            exit;
        }
        
        // intercept login action
        else if ($args['action'] == 'login') {
            // kill current session
            $rcmail->kill_session();
            
            // initialize CAS client
            $this->init_cas();

            // attempt to authenticate with CAS server
            if (phpCAS::forceAuthentication()) {
                // retrieve authenticated credentials
                $host = $rcmail->autoselect_host();
                $user = phpCAS::getUser();
                if ($cfg['cas_proxy']) {
                    $password = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
                }
                else {
                    $password = $cfg['cas_imap_password'];
                }

                // restore original request parameters
                $query = array();
                if ($url = $_COOKIE['cas_url']) {
                    parse_str($url, $query);
                }

                // attempt to login
                if ($_SESSION['temp'] && !empty($host) && !empty($user) && isset($password)
                && $rcmail->login($user, $password, $host)) {
                    // create new session ID
                    rcube_sess_unset('temp');
                    rcube_sess_regenerate_id();

                    // send auth cookie if necessary
                    $rcmail->authenticate_session();

                    // allow plugins to control redirection url, default to original request url
                    $redirect_url = $rcmail->plugins->exec_hook('login_after', $query);
                    unset($redirect_url['abort']);

                    // redirect
                    $rcmail->output->redirect($redirect_url);
                }
                
                // login failed
                else {
                    // handle IMAP connection failure
                    $this->imap_failure();
                }
            }
        }

        // intercept logout task
        else if ($args['task'] == 'logout') {
            // still logged into Roundcube
            if (isset($_SESSION['user_id'])) {
                // perform Roundcube logout routines
                $rcmail->logout_actions();
                $rcmail->kill_session();
            }

            // initialize CAS client
            $this->init_cas();

            // logout from CAS server
            phpCAS::logout();
            
            // end script
            exit;
        }

        return $args;
    }

    /**
     * Intercept page rendering actions
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function render_page($args) {
        // intercept login template rendering in order to replace login form with CAS request
        if ($args['template'] == 'login') {
            // retrieve rcmail instance
            $rcmail = rcmail::get_instance();
            
            // save request url to a cookie
            $url = get_input_value('_url', RCUBE_INPUT_POST);
            if (empty($url) && !preg_match('/_task=logout/', $_SERVER['QUERY_STRING'])) {
                $url = $_SERVER['QUERY_STRING'];
            }
            setcookie('cas_url', $url);

            // set redirection url
            $rcmail->action = 'login';
            $redirect_url = array('action' => $rcmail->action);

            // redirect to login action
            $rcmail->output->redirect($redirect_url);
        }
        
        return $args;
    }
    
    /**
     * Intercept connection to IMAP server using stored session data
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function imap_connect($args) {
        // IMAP connection is not established
        if (!$args['connected']) {
            // retrieve rcmail instance
            $rcmail = rcmail::get_instance();

            // retrieve configurations
            $cfg = $rcmail->config->all();

            // Roundcube is acting as CAS proxy
            if ($cfg['cas_proxy']) {
                // the IMAP server caches proxy tickets
                if ($cfg['cas_imap_caching']) {
                    // attempt to connect to IMAP server
                    if ($rcmail->imap->connect($_SESSION['imap_host'], $_SESSION['username'], $rcmail->decrypt($_SESSION['password']), $_SESSION['imap_port'], $_SESSION['imap_ssl'])) {
                        // connection is successful, so no need to retrieve new proxy ticket
                        $args['connected'] = true;
                        return $args;
                    }
                }

                // the IMAP server doesn't cache proxy tickets or the cache has expired
                // initialize CAS client
                $this->init_cas();

                // retrieve and store a new proxy ticket in session
                if (phpCAS::forceAuthentication()) {
                    $_SESSION['password']  = $rcmail->encrypt(phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output));
                }
            }
        }
        
        return $args;
    }
    
    /**
     * Initialize CAS client
     * 
     */
    private function init_cas() {
        // retrieve configurations
        $cfg = rcmail::get_instance()->config->all();

        // include phpCAS
        require_once('CAS.php');
        
        // initialize CAS client
        if ($cfg['cas_proxy']) {
            phpCAS::proxy(CAS_VERSION_2_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], false);
            
            // set URL for PGT callback
            phpCAS::setFixedCallbackURL($this->generate_url(array('action' => 'pgtcallback')));
        }
        else {
            phpCAS::client(CAS_VERSION_2_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], false);
        }
        
        // set service URL for authorization with CAS server
        phpCAS::setFixedServiceURL($this->generate_url(array('action' => 'login')));

        // set SSL validation for the CAS server
        if ($cfg['cas_validation'] == 'self') {
            phpCAS::setCasServerCert($cfg['cas_cert']);
        }
        else if ($cfg['cas_validation'] == 'ca') {
            phpCAS::setCasServerCACert($cfg['cas_cert']);
        }
        else {
            phpCAS::setNoCasServerValidation();
        }
        
        // set login and logout URLs of the CAS server
        phpCAS::setServerLoginURL($cfg['cas_login_url']);
        phpCAS::setServerLogoutURL($cfg['cas_logout_url']);
    }

    /**
     * Handle IMAP connection failures
     *
     */
    private function imap_failure() {
        // retrieve roundcube instance
        $rcmail = rcmail::get_instance();
        
        // compose error page content
        global $__page_content, $__error_title, $__error_text;
        $__error_title = "IMAP LOGIN FAILED";
        $__error_text  = <<<EOF
Could not log into your IMAP service. The service may be interrupted, or you may not be authorized to access the service.<br />
Please contact the administrator of your IMAP service.<br />
Or log out by clicking on the button below, then try again with a different user name.<br />
EOF;
        $__page_content = <<<EOF
<div>
<h3 class="error-title">$__error_title</h3>
<p class="error-text">$__error_text</p>
<form name="form" action="./" method="get">
<input type="hidden" name="_task" value="logout" />
<p style="text-align:center;"><input type="submit" class="button mainaction" value="Logout" /></p>
</form>
</div>
EOF;
        
        // redirect to error page
        $rcmail->output->reset();
        $rcmail->output->send('error');
        
        // kill current session
        $rcmail->kill_session();
        
        // end script
        exit;
    }
    
    /**
     * Build full URLs to this instance of Roundcube for use with CAS servers
     * 
     * @param array $params url parameters as key-value pairs
     * @return string full Roundcube URL
     */
    private function generate_url($params) {
        $s = ($_SERVER['HTTPS'] == 'on') ? 's' : '';
        $protocol = $this->strleft(strtolower($_SERVER['SERVER_PROTOCOL']), '/') . $s;
        $port = (($_SERVER['SERVER_PORT'] == '80' && $_SERVER['HTTPS'] != 'on') ||
                 ($_SERVER['SERVER_PORT'] == '443' && $_SERVER['HTTPS'] == 'on')) ? 
                '' : (':' .$_SERVER['SERVER_PORT']);
        $path = $this->strleft($_SERVER['REQUEST_URI'], '?');
        $parsed_params = '';
        $delm = '?';
        foreach (array_reverse($params) as $key => $val) {
            if (!empty($val)) {
                $parsed_key = $key[0] == '_' ? $key : '_' . $key;
                $parsed_params .= $delm . urlencode($parsed_key) . '=' . urlencode($val);
                $delm = '&';
            }
        }
        return $protocol . '://' . $_SERVER['SERVER_NAME'] . $port . $path . $parsed_params;
    }

    private function strleft($s1, $s2) {
        $length = strpos($s1, $s2);
        if ($length) {
            return substr($s1, 0, $length);
        }
        else {
            return $s1;
        }
    }
}
?>