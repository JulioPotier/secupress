<?php
/*
Module Name: Logins Blacklist
Description: Forbid some usernames to be used.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* EXISTING USERS WITH A BLACKLISTED USERNAME MUST CHANGE IT. =================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * As soon as we are sure a user is connected, and before any redirection, check if the user login is not blacklisted.
 * If he is, he can't access the administration area and is asked to change it.
 *
 * @since 1.0
 */
add_action( 'auth_redirect', 'secupress_auth_redirect_blacklist_logins' );

function secupress_auth_redirect_blacklist_logins( $user_id ) {

	$user = get_userdata( $user_id );
	$list = secupress_get_blacklisted_usernames();
	$list = array_flip( $list );

	if ( ! isset( $list[ $user->user_login ] ) ) {
		// Good, the login is not blacklisted.
		return;
	}

	$nonce_action = 'secupress-backlist-logins-new-login-' . $user_id;
	$error        = '';

	// A new login is submitted.
	if ( isset( $_POST['secupress-backlist-logins-new-login'] ) ) {

		if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
			wp_die( __( 'Cheatin&#8217; uh?' ) );
		}

		if ( empty( $_POST['secupress-backlist-logins-new-login'] ) ) {
			// Empty username.
			$error = __( 'Username required', 'secupress' );
		} else {
			// Sanitize the submitted username.
			$user_login = sanitize_user( $_POST['secupress-backlist-logins-new-login'], true );

			if ( isset( $list[ $user_login ] ) ) {
				// The new login is blacklisted.
				$error = __( 'This username is also blacklisted', 'secupress' );
			} else {
				// Good, change the user login.
				$inserted = secupress_blacklist_logins_change_user_login( $user_id, $user_login );

				if ( is_wp_error( $inserted ) ) {
					// Too bad, try again.
					$error = $inserted->get_error_message();
				} else {
					// Send the new login by email.
					secupress_blacklist_logins_new_user_notification( $user_id );

					// Kill Bill session.
					wp_clear_auth_cookie();
					wp_destroy_current_session();

					// Redirect the user to the login page.
					$login_url = wp_login_url( secupress_get_current_url( 'raw' ), true );
					$login_url = add_query_arg( 'secupress-relog', 1, $login_url );
					wp_redirect( $login_url );
					exit();
				}
			}
		}
	}

	// Allowed characters for the login.
	$allowed = esc_attr( secupress_blacklist_logins_allowed_characters() );

	// The form.
	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php _e( 'Please change your username', 'secupress' ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<style>
html, body {
	width: 100%;
	margin: 0;
	font: 1em/1.5 Arial, Helvetica, sans-serif;
	color: #313131;
	background: #F1F1F1;
}
form,
div {
	max-width: 400px;
	padding: 20px 10px;
	margin: 10px auto;
}
div {
	text-align: center;
}
h1 {
	margin: 0 0 1em;
	font-size: 2em;
	line-height: 1.1;
}
p {
	margin: 0 0 1.5em;
}
a {
	color: #205081;
}
a:active,
a:hover,
a:focus {
	color: #2d75bd;
}
.error {
	padding: .5em 1em;
	border: solid 2px #ff8383;
	background: #ffb1b1;
	border-radius: .2em;
}
label {
	display: inline-block;
	margin-bottom: .5em;
}
[type="text"] {
	box-sizing: border-box;
	width: 100%;
	padding: .5em;
	border: 1px solid rgba(83,69,55,.3);
	margin: 0 0 1.5em;
	border-radius: 3px;
	font-size: 1em;
	font-family: inherit;
	color: inherit;
}
[type="text"]:focus {
	border-color: rgb(156,144,138);
}
[type="submit"] {
	position: relative;
	display: inline-block;
	line-height: 1.2;
	padding: .65em 1.8em;
	border: none;
	margin: 0 0 .5em 0;
	background: #205081;
	-webkit-appearance: none;
	   -moz-appearance: none;
	        appearance: none;
	box-shadow: none;
	border-radius: .214em;
	color: #fff;
	font-size: .875em;
	font-family: inherit;
	text-align: center;
	text-transform: uppercase;
	text-decoration: none;
	vertical-align: middle;
	cursor: pointer;
	-webkit-transition: all .3s ease;
	        transition: all .3s ease;
}
[type="submit"]:focus,
[type="submit"]:hover {
	background-color: #2d75bd;
}
		</style>
	</head>
	<body>
		<form method="post">
			<h1><?php _e( 'Please change your username', 'secupress' ); ?></h1>
			<p><?php
			printf(
				/* translators: 1 is a user name, 2 is a link "to the site" */
				__( 'Your current username %1$s is blacklisted. You will not be able to reach the administration area until you change your username. Meanwhile, you still have access %2$s.', 'secupress' ),
				'<strong>' . esc_html( $user->user_login ) . '</strong>',
				'<a href="' . esc_url( user_trailingslashit( home_url() ) ) . '">' . __( 'to the site', 'secupress' ) . '</a>'
			);
			?></p>
			<?php
			if ( $error ) {
				echo '<p class="error">' . $error . '</p>';
			}
			?>
			<label for="new-login"><?php _e( 'New username:', 'secupress' ); ?></label><br/>
			<input type="text" id="new-login" name="secupress-backlist-logins-new-login" value="" maxlength="60" required="required" aria-required="true" pattern="[A-Za-z0-9 _.\-@]{2,60}" autocorrect="off" autocapitalize="off" title="<?php echo $allowed; ?>"/><br/>
			<input type="submit" />
			<?php wp_nonce_field( $nonce_action ) ?>
		</form>
	</body>
</html><?php
	die();
}


/*
 * Display a message on the login form after the new login creation.
 *
 * @since 1.0
 *
 * @param (object) $errors      WP Error object.
 * @param (string) $redirect_to Redirect destination URL.
 *
 * @return (object) WP Error object.
 */
add_filter( 'wp_login_errors', 'secupress_blacklist_logins_display_login_message', 10, 2 );

function secupress_blacklist_logins_display_login_message( $errors, $redirect_to ) {
	if ( empty( $_GET['secupress-relog'] ) ) {
		return $errors;
	}

	if ( empty( $errors ) ) {
		$errors = new WP_Error();
	}

	$errors->add( 'secupress_relog', __( 'You will receive your new login in your mailbox.', 'secupress' ), 'message' );

	return $errors;
}


/*------------------------------------------------------------------------------------------------*/
/* UTILITIES ==================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Change a user login.
 *
 * @since 1.0
 *
 * @param (int)    $user_id    I let you guess what it is.
 * @param (string) $user_login Well...
 *
 * @return (int|object) User ID or WP_Error object on failure.
 */
function secupress_blacklist_logins_change_user_login( $user_id, $user_login ) {
	global $wpdb;

	// user_login must be between 1 and 60 characters.
	if ( empty( $user_login ) ) {
		return new WP_Error( 'empty_user_login', __( 'Cannot create a user with an empty login name.' ) );
	} elseif ( mb_strlen( $user_login ) > 60 ) {
		return new WP_Error( 'user_login_too_long', __( 'Username may not be longer than 60 characters.' ) );
	}

	if ( username_exists( $user_login ) ) {
		return new WP_Error( 'existing_user_login', __( 'Sorry, that username already exists!' ) );
	}

	$wpdb->update( $wpdb->users, array( 'user_login' => $user_login ), array( 'ID' => $user_id ) );

	wp_cache_delete( $user_id, 'users' );
	wp_cache_delete( $user_login, 'userlogins' );

	secupress_scanit( 'Bad_Usernames' );

	return $user_id;
}


/*
 * Send an email notification to a user with his/her login.
 *
 * @since 1.0
 *
 * @param (int|object) $user A user ID or a user object.
 */
function secupress_blacklist_logins_new_user_notification( $user ) {
	$user = is_object( $user ) ? $user : get_userdata( $user );

	// The blogname option is escaped with esc_html on the way into the database in sanitize_option
	// we want to reverse this for the plain text arena of emails.
	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	$message  = sprintf( __( 'Username: %s' ), $user->user_login ) . "\r\n\r\n"; // WP i18n
	$message .= wp_login_url() . "\r\n";

	wp_mail( $user->user_email, sprintf( __( '[%s] Your username info', 'secupress' ), $blogname ), $message );
}


/*
 * Get the blacklisted usernames.
 *
 * @since 1.0
 *
 * @return (array)
 */
function secupress_get_blacklisted_usernames() {
	// Blacklisted usernames.
	$list = array(
		'a', 'admin', 'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
		'b', 'backup', 'banner', 'banners', 'bin', 'billing', 'blog', 'blogs', 'board', 'bot', 'bots', 'business',
		'c', 'chat', 'cache', 'cadastro', 'calendar', 'campaign', 'careers', 'cdn', 'cgi', 'client', 'cliente', 'code', 'comercial', 'compare', 'config', 'connect', 'contact', 'contest', 'create', 'code', 'compras', 'css',
		'd', 'dashboard', 'data', 'db', 'design', 'delete', 'demo', 'design', 'designer', 'dev', 'devel', 'dir', 'directory', 'doc', 'documentation', 'docs', 'domain', 'download', 'downloads',
		'e', 'edit', 'editor', 'email', 'ecommerce',
		'f', 'forum', 'forums', 'faq', 'favorite', 'feed', 'feedback', 'flog', 'follow', 'file', 'files', 'free', 'ftp',
		'g', 'gadget', 'gadgets', 'games', 'guest', 'group', 'groups',
		'h', 'help', 'home', 'homepage', 'host', 'hosting', 'hostname', 'htm', 'html', 'http', 'httpd', 'https', 'hpg',
		'i', 'info', 'information', 'image', 'img', 'images', 'imap', 'index', 'invite', 'intranet', 'indice', 'ipad', 'iphone', 'irc',
		'j', 'java', 'javascript', 'job', 'jobs', 'js',
		'k', 'knowledgebase',
		'l', 'log', 'login', 'logs', 'logout', 'list', 'lists',
		'm', 'mail', 'mail1', 'mail2', 'mail3', 'mail4', 'mail5', 'mailer', 'mailing', 'mx', 'manager', 'marketing', 'master', 'me', 'media', 'message', 'microblog', 'microblogs', 'mine', 'mp3', 'msg', 'msn', 'mysql', 'messenger', 'mob', 'mobile', 'movie', 'movies', 'music', 'musicas', 'my',
		'n', 'name', 'named', 'net', 'network', 'new', 'news', 'newsletter', 'nick', 'nickname', 'notes', 'noticias', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9',
		'o', 'old', 'online', 'operator', 'order', 'orders',
		'p', 'page', 'pager', 'pages', 'panel', 'password', 'perl', 'pic', 'pics', 'photo', 'photos', 'photoalbum', 'php', 'plugin', 'plugins', 'pop', 'pop3', 'post', 'postmaster', 'postfix', 'posts', 'private', 'profile', 'project', 'projects', 'promo', 'pub', 'public', 'python',
		'q',
		'r', 'random', 'register', 'registration', 'root', 'ruby', 'rss',
		's', 'sale', 'sales', 'sample', 'samples', 'script', 'scripts', 'secure', 'send', 'service', 's'.'e'.'x', 'shop', 'sql', 'signup', 'signin', 'search', 'security', 'settings', 'setting', 'setup', 'site', 'sites', 'sitemap', 'smtp', 'soporte', 'ssh', 'stage', 'staging', 'start', 'subscribe', 'subdomain', 'suporte', 'support', 'stat', 'static', 'stats', 'status', 'store', 'stores', 'system',
		't', 'tablet', 'tablets', 'tech', 'telnet', 'test', 'test1', 'test2', 'test3', 'teste', 'tests', 'theme', 'themes', 'tmp', 'todo', 'task', 'tasks', 'tools', 'tv', 'talk',
		'u', 'update', 'upload', 'url', 'user', 'username', 'usuario', 'usage',
		'v', 'vendas', 'video', 'videos', 'visitor',
		'w', 'win', 'ww', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www9', 'www9', 'wwww', 'wws', 'wwws', 'web', 'webmail', 'website', 'websites', 'webmaster', 'workshop',
		'x', 'xxx', 'xpg',
		'y', 'you',
		'z',
		'_', '.', '-', '@',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	);

	$list = apply_filters( 'secupress.plugin.blacklist_logins_list', $list );

	// Temporarily allow some blacklisted usernames.
	$allowed = (array) secupress_cache_data( 'allowed_usernames' );
	if ( $allowed ) {
		$list = array_diff( $list, $allowed );
		secupress_cache_data( 'allowed_usernames', array() );
	}

	return $list;
}


/*
 * Tell if a username is blacklisted.
 *
 * @since 1.0
 *
 * @param (string) $username The username to test.
 *
 * @return (bool) true if blacklisted.
 */
function secupress_is_username_blacklisted( $username ) {
	$list = secupress_get_blacklisted_usernames();
	$list = array_flip( $list );
	return isset( $list[ mb_strtolower( $username ) ] );
}


/*
 * Logins blacklist: return the list of allowed characters for the usernames.
 *
 * @since 1.0
 *
 * @param (bool) $wrap If set to true, the characters will be wrapped with `code` tags.
 *
 * @return (string)
 */
function secupress_blacklist_logins_allowed_characters( $wrap = false ) {
	$allowed = is_multisite() ? array( 'a-z', '0-9', ) : array( 'A-Z', 'a-z', '0-9', '(space)', '_', '.', '-', '@', );
	if ( $wrap ) {
		foreach ( $allowed as $i => $char ) {
			$allowed[ $i ] = '<code>' . $char . '</code>';
		}
	}
	$allowed = wp_sprintf_l( '%l', $allowed );

	return sprintf( __( 'Allowed characters: %s.', 'secupress' ), $allowed );
}


/*------------------------------------------------------------------------------------------------*/
/* FORBID USER CREATION AND EDITION IF THE USERNAME IS BLACKLISTED. ============================= */
/*------------------------------------------------------------------------------------------------*/

// Launch the filters.

// `register_new_user()`.
add_filter( 'registration_errors', 'secupress_blacklist_logins_registration_errors', 10, 2 );

if ( secupress_wp_version_is( '4.4-RC1' ) ) :

	// `edit_user()`, `wpmu_validate_user_signup()` and `wp_insert_user()`.
	add_filter( 'illegal_user_logins', 'secupress_blacklist_logins_illegal_user_logins' );

else :

	// `edit_user()`.
	add_action( 'user_profile_update_errors', 'secupress_blacklist_logins_user_profile_update_errors', 10, 3 );
	// `wpmu_validate_user_signup()`.
	add_filter( 'wpmu_validate_user_signup', 'secupress_blacklist_logins_wpmu_validate_user_signup' );
	// `wp_insert_user()`.
	add_filter( 'pre_user_login', 'secupress_blacklist_logins_pre_user_login' );

endif;


/*
 * In `register_new_user()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (object) $errors               A WP_Error object containing any errors encountered during registration.
 * @param (string) $sanitized_user_login User's username after it has been sanitized.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_registration_errors( $errors, $sanitized_user_login ) {
	if ( secupress_is_username_blacklisted( $sanitized_user_login ) ) {
		$errors->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $errors;
}


/*
 * Filter the blacklisted user names.
 * This filter is used in `wp_insert_user()`, `edit_user()` and `wpmu_validate_user_signup()`.
 *
 * @since 1.0
 *
 * @param (array) $usernames A list of forbidden user names.
 *
 * @return (array) The forbidden user names.
 */
function secupress_blacklist_logins_illegal_user_logins( $usernames ) {
	return array_merge( $usernames, secupress_get_blacklisted_usernames() );
}


/*
 * In `edit_user()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (object) $errors A WP_Error object, passed by reference.
 * @param (bool)   $update Whether this is a user update.
 * @param (object) $user   A WP_User object, passed by reference.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_user_profile_update_errors( $errors, $update, $user ) {
	if ( secupress_is_username_blacklisted( $user->user_login ) ) {
		$errors->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $errors;
}


/*
 * In `wpmu_validate_user_signup()`, detect forbidden logins.
 *
 * @since 1.0
 *
 * @param (array) $result An array containing the sanitized user name, the original one, the user email, and a `WP_Error` object.
 *
 * @return (array) The array with a new error if the user name is blacklisted.
 */
function secupress_blacklist_logins_wpmu_validate_user_signup( $result ) {
	if ( secupress_is_username_blacklisted( $result['user_name'] ) ) {
		$result['errors']->add( 'user_name',  __( 'Sorry, that username is not allowed.', 'secupress' ) );
	}
	return $result;
}


/*
 * In `wp_insert_user()`, detect forbidden logins.
 * If the username is in the blacklist, an empty username will be returned, triggering a `empty_user_login` error later.
 *
 * @since 1.0
 *
 * @param (string) $sanitized_user_login Current user login.
 *
 * @return (string) The user login or an empty string if blacklisted.
 */
function secupress_blacklist_logins_pre_user_login( $sanitized_user_login ) {
	if ( secupress_is_username_blacklisted( $sanitized_user_login ) ) {
		// Filter the `empty_user_login` error message.
		add_filter( 'gettext', 'secupress_blacklist_logins_gettext_filter', 8, 3 );
		return '';
	}
	return $sanitized_user_login;
}


/*
 * After a blacklisted username is detected, filter the `empty_user_login` error message.
 *
 * @since 1.0
 *
 * @param (string) $translations Translated text.
 * @param (string) $text Original text.
 * @param (string) $domain Text domain.
 *
 * @return (string) The translation.
 */
function secupress_blacklist_logins_gettext_filter( $translations, $text, $domain ) {
	if ( 'Cannot create a user with an empty login name.' === $text && 'default' === $domain ) {
		// No need to filter gettext anymore.
		remove_filter( 'gettext', 'secupress_blacklist_logins_gettext_filter', 8 );
		return __( 'Sorry, that username is not allowed.', 'secupress' );
	}
	return $translations;
}
