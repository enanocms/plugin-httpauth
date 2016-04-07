<?php
/**!info**
{
  "Plugin Name"  : "HTTP authentication",
  "Plugin URI"   : "http://enanocms.org/plugin/httpauth",
  "Description"  : "Allows authentication to Enano via HTTP authentication.",
  "Author"       : "Dan Fuhry",
  "Version"      : "1.0",
  "Author URI"   : "http://enanocms.org/",
  "Auth plugin"  : true
}
**!*/

/*
 * HTTP authentication plugin for Enano
 * (C) 2014 Dan Fuhry
 *
 * This program is Free Software; you can redistribute and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 */

if ( getConfig('http_auth_enable', 0) == 1 )
{
  $plugins->attachHook('compile_template', 'http_auth_attach_headers($this);');
  $plugins->attachHook('login_form_html', 'http_auth_login_html();');
}

function http_auth_attach_headers(&$template)
{
    global $db, $session, $paths, $template, $plugins; // Common objects
    
    $template->add_header('<script type="text/javascript" src="' . scriptPath . '/plugins/httpauth/login-hook.js"></script>');
}

function http_auth_login_html()
{
	global $db, $session, $paths, $template, $plugins; // Common objects
	
	global $output;
	
	ob_end_clean();
	
	$return = ($goto = $paths->getAllParams()) !== '' ? $goto : get_main_page();
	$qs = ( isset($_GET['level']) ) ? 'level=' . $_GET['level'] : '';
	
	$uri = makeUrlNS('Special', 'LoginHTTP/' . $return, $qs);
	
	redirect($uri, '', '', 0);
	exit;
}

// Registration blocking hook
if ( getConfig('http_auth_disable_local', 0) == 1 )
{
  $plugins->attachHook('ucp_register_validate', 'http_auth_reg_block($error);');
}

function http_auth_reg_block(&$error)
{
  $error = 'Registration on this website is disabled because HTTP authentication is configured. Please log in using a valid username and password, and an account will be created for you automatically.';
}

$plugins->attachHook('session_started', 'http_auth_add_special();');
 
function http_auth_add_special()
{
  register_special_page('LoginHTTP', 'Login with HTTP Authentication', true);
}
 
function page_Special_LoginHTTP()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  global $output;
  
  if ( isset($_GET['level']) ) {
    $result = array('result' => 'error');
    
    if ( !empty($_SERVER['REMOTE_USER']) ) {
      $level = intval($_GET['level']);
      if ( $level > USER_LEVEL_MEMBER ) {
        $username = $db->escape(strtolower($_SERVER['REMOTE_USER']));
        
        $q = $db->sql_query("SELECT user_id, password, user_level FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
        if ( !$q )
          $db->_die();
        
        if ( $db->numrows() == 1 ) {
          $row = $db->fetchrow();
          
          if ( $row['user_level'] < $level ) {
            die_friendly('Access denied', '<p>Not permitted to authenticate at this level.</p>');
          }
          
          $session->register_session($row['user_id'], $_SERVER['REMOTE_USER'], $row['password'], $level, $remember);
          
          $result = array(
            'result' => 'success',
            'sid' => $session->sid_super
            );
        }
        
        $db->free_result();
      }
    }
    
    if ( isset($_GET['ajax']) ) {
		$output = new Output_Naked;
		header('Content-type: text/javascript');
		echo json_encode($result);
		
		return;
	}
  }
  else
  {
	  if ( empty($_SERVER['REMOTE_USER']) ) {
		die_friendly('No HTTP authentication supplied', '<p>This site is configured for HTTP authentication, but none was supplied by the webserver software. Please verify your webserver configuration.</p>');
	  }
	  
	  http_auth_do_login();
  }
  
  $return = ($goto = $paths->getAllParams()) !== '' ? $goto : get_main_page();
  redirect(makeUrl($return), 'Logged in', 'You have successfully logged in using HTTP authentication. You will be momentarily taken to your destination.', 3);
}

function http_auth_do_login()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  $user = $_SERVER['REMOTE_USER'];
  
  $username = $db->escape(strtolower($user));
  
  $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
  if ( !$q )
    $db->_die();
  
  if ( $db->numrows() < 1 )
  {
    // This user doesn't exist.
    // Is creating it our job?
    if ( getConfig('http_auth_disable_local', 0) == 1 )
    {
      // Yep, register him
      $email = strtolower($user) . '@' . getConfig('http_auth_email_domain', 'localhost');
      $random_pass = md5(microtime() . mt_rand());
      // load the language
      $session->register_guest_session();
      $reg_result = $session->create_user($user, $random_pass, $email);
      if ( $reg_result != 'success' )
      {
        // o_O
        // Registration failed.
        die_friendly('HTTP authentication error', '<p>Your username and password were valid, but there was a problem instanciating your local user account: ' . $reg_result . '.</p>');
      }
      // Get user ID
      $q = $db->sql_query("SELECT user_id, password FROM " . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '$username';");
      if ( !$q )
        $db->_die();
      if ( $db->numrows() < 1 ) {
        die_friendly('HTTP authentication error', '<p>Your username and password were valid, but there was a problem getting your user ID.</p>');
      }
      $row = $db->fetchrow();
      $db->free_result();
      // Quick - lock the account
      $q = $db->sql_query('UPDATE ' . table_prefix . "users SET password = 'Locked by HTTP auth plugin', password_salt = 'Locked by HTTP auth plugin' WHERE user_id = {$row['user_id']};");
      if ( !$q )
        $db->_die();
      
      $row['password'] = 'Locked by HTTP auth plugin';
    }
    else
    {
      // Nope. Just let Enano fail it properly.
      die_friendly('User does not exist', '<p>You\'ve attempted to log in with an account that doesn\'t exist, and the HTTP Authentication plugin is not configured to auto-create new accounts.</p>');
    }
  }
  else
  {
    $row = $db->fetchrow();
    $db->free_result();
  }
  
  $session->register_session($row['user_id'], $user, $row['password'], $level, $remember);
}

//
// ADMIN
//

$plugins->attachHook('session_started', 'http_auth_session_hook();');

if ( getConfig('http_auth_disable_local', 0) == 1 )
{
  $plugins->attachHook('common_post', 'http_auth_tou_hook();');
}

function http_auth_session_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Register the admin page
  $paths->addAdminNode('adm_cat_security', 'HTTP Authentication', 'HTTPAuthConfig');
  
  // Disable password change
  if ( getConfig('http_auth_disable_local', 0) == 1 && $session->user_level < USER_LEVEL_ADMIN )
  {
    $link_text = getConfig('http_auth_password_text', false);
    if ( empty($link_text) )
      $link_text = false;
    $link_url = str_replace('%u', $session->username, getConfig('http_auth_password_url', ''));
    if ( empty($link_url) )
      $link_url = false;
    $session->disable_password_change($link_url, $link_text);
  }
}

function clean_server_redirect_vars()
{
  foreach ( $_SERVER as $key => $value ) {
    if ( preg_match($regexp = '/^(REDIRECT_)*/', $key) )
    {
      $newkey = preg_replace($regexp, '', $key);
      if ( !isset($_SERVER[$newkey]) )
      {
        $_SERVER[$newkey] = $value;
      }
    }
  }
}

function http_auth_tou_hook()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  // Are we supposed to fail if no authentication information is presented?
  // first strip REDIRECT_* from $_SERVER variables
  clean_server_redirect_vars();
  
  if ( getConfig('http_auth_mode', 'guest') === 'noguest' && empty($_SERVER['REMOTE_USER']) )
  {
    die_friendly('No authentication provided', '<p>This Enano website is configured to require HTTP authentication for all pages, but none was provided by the webserver software. Please check your webserver configuration.</p>');
  }
  
  if ( !empty($_SERVER['REMOTE_USER']) && !$session->user_logged_in && !in_array($paths->page, array('Special:Login', 'Special:LoginHTTP', 'Special:Logout')) ) {
    http_auth_do_login();
    redirect($paths->page, '', '', 0);
  }
  
  // Are we pending TOU acceptance?
  if ( $session->user_logged_in && !$session->on_critical_page() && trim(getConfig('register_tou', '')) != '' )
  {
    $q = $db->sql_query('SELECT account_active FROM ' . table_prefix . "users WHERE user_id = {$session->user_id};");
    if ( !$q )
      $db->_die();
    
    list($active) = $db->fetchrow_num();
    $db->free_result();
    if ( $active == 1 )
    {
      // Pending TOU accept
      // Basically, what we do here is force the user to accept the TOU and record it by setting account_active to 2 instead of a 1
      // A bit of a hack, but hey, it works, at least in 1.1.8.
      // In 1.1.7, it just breaks your whole account, and $session->on_critical_page() is broken in 1.1.7 so you won't even be able
      // to go the admin CP and re-activate yourself. Good times... erhm, sorry.
      
      if ( isset($_POST['tou_agreed']) && $_POST['tou_agreed'] === 'I accept the terms and conditions displayed on this site' )
      {
        // Accepted
        $q = $db->sql_query('UPDATE ' . table_prefix . "users SET account_active = 2 WHERE user_id = {$session->user_id};");
        if ( !$q )
          $db->_die();
        
        return true;
      }
      
      global $output, $lang;
      $output->set_title('Terms of Use');
      $output->header();
      
      ?>
      <p>Please read and accept the following terms:</p>
      
      <div style="border: 1px solid #000000; height: 300px; width: 60%; clip: rect(0px,auto,auto,0px); overflow: auto; background-color: #FFF; margin: 0 auto; padding: 4px;">
        <?php
        $terms = getConfig('register_tou', '');
        echo RenderMan::render($terms);
        ?>
      </div>
      
      <form method="post">
        <p style="text-align: center;">
          <label>
            <input tabindex="7" type="checkbox" name="tou_agreed" value="I accept the terms and conditions displayed on this site" />
            <b><?php echo $lang->get('user_reg_lbl_field_tou'); ?></b>
          </label>
        </p>
        <p style="text-align: center;">
          <input type="submit" value="Continue" />
        </p>
      </form>
      
      <?php
      
      $output->footer();
      
      $db->close();
      exit;
    }
  }
}

function page_Admin_HTTPAuthConfig()
{
  // Security check
  global $db, $session, $paths, $template, $plugins; // Common objects
  if ( $session->auth_level < USER_LEVEL_ADMIN )
    return false;
  
  if ( isset($_POST['submit']) )
  {
    setConfig('http_auth_enable', isset($_POST['http_auth_enable']) ? '1' : '0');
    setConfig('http_auth_disable_local', isset($_POST['http_auth_disable_local']) ? '1' : '0');
    setConfig('http_auth_mode', isset($_POST['http_auth_mode']) && in_array($_POST['http_auth_mode'], array('guest', 'noguest')) ? $_POST['http_auth_mode'] : 'guest');
    setConfig('http_auth_password_text', $_POST['http_auth_password_text']);
    setConfig('http_auth_password_url', $_POST['http_auth_password_url']);
    setConfig('http_auth_email_domain', $_POST['http_auth_email_domain']);
    
    echo '<div class="info-box">Your changes have been saved.</div>';
  }
  
  acp_start_form();
  ?>
  <div class="tblholder">
    <table border="0" cellspacing="1" cellpadding="4">
      <tr>
        <th colspan="2">
          HTTP Authentication Configuration
        </th>
      </tr>
      
      <!-- HTTP enable -->
      
      <tr>
        <td class="row2" style="width: 50%;">
          Enable HTTP authentication:
        </td>
        <td class="row1" style="width: 50%;">
          <label>
            <input type="checkbox" name="http_auth_enable" <?php if ( getConfig('http_auth_enable', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- Block local auth -->
      
      <tr>
        <td class="row2">
          Enforce HTTP for single-sign-on:<br />
          <small>Use this option to force HTTP passwords and accounts to be used, regardless of local accounts, except for administrators.</small>
        </td>
        <td class="row1">
          <label>
            <input type="checkbox" name="http_auth_disable_local" <?php if ( getConfig('http_auth_disable_local', 0) ) echo 'checked="checked" '; ?>/>
            Enabled
          </label>
        </td>
      </tr>
      
      <!-- Auth mode -->
      
      <tr>
        <td class="row2" rowspan="2">
          Guest access mode:<br />
          <small>You can allow guests to browse the site without logging in, and configure your webserver to require authentication only on the login page URL given below. Or, you can require authentication across the whole site. In the latter case, if the webserver fails to provide any authentication state, page loads will fail.</small>
        </td>
        <td class="row1">
          <label>
            <input type="radio" name="http_auth_mode" value="guest" <?php if ( getConfig('http_auth_mode', 'guest') === 'guest' ) echo 'checked="checked" '; ?>/>
            Guests allowed
          </label>
          
          <label>
            <input type="radio" name="http_auth_mode" value="noguest" <?php if ( getConfig('http_auth_mode', 'guest') === 'noguest' ) echo 'checked="checked" '; ?>/>
            Fail without authentication
          </label>
        </td>
      </tr>
      
      <tr>
        <td class="row3">
          Login page URL:
            <input size="45" type="text" readonly="readonly" value="<?php echo htmlspecialchars(preg_replace('/[?&]auth=[a-f0-9]+/', '', makeUrlComplete('Special', 'LoginHTTP'))); ?>" />
          
          <br />
          <small>Set this URL to require authentication in your webserver's configuration.</small>
        </td>
      </tr>
      
      <!-- E-mail domain -->
      
      <tr>
        <td class="row2">
          E-mail address domain for autoregistered users:<br />
          <small>When a user is automatically registered, this domain will be used as the domain for their e-mail address. This way, activation e-mails will
                 (ideally) reach the user.</small>
        </td>
        <td class="row1">
          <input type="text" name="http_auth_email_domain" value="<?php echo htmlspecialchars(getConfig('http_auth_email_domain', '')); ?>" size="30" />
        </td>
      </tr>
      
      <!-- Site password change link -->
      
      <tr>
        <td class="row2">
          External password management link:<br />
          <small>Enter a URL here to link to from Enano's Change Password page. Leave blank to not display a link. The text "%u" will be replaced with the user's username.</small>
        </td>
        <td class="row1">
          Link text: <input type="text" name="http_auth_password_text" value="<?php echo htmlspecialchars(getConfig('http_auth_password_text', '')); ?>" size="30" /><br />
          Link URL:  <input type="text" name="http_auth_password_url" value="<?php echo htmlspecialchars(getConfig('http_auth_password_url', '')); ?>" size="30" />
        </td>
      </tr>
      
      <tr>
        <th class="subhead" colspan="2">
          <input type="submit" name="submit" value="Save changes" />
        </th>
      </tr>
    </table>
  </div>
  <?php
  echo '</form>';
}
