<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized an validated settings.
 */
function __secupress_users_login_settings_callback( $settings ) {
	$modulenow    = 'users-login';
	$settings     = $settings ? $settings : array();
	$old_settings = get_site_option( "secupress_{$modulenow}_settings" );

	unset( $settings['temp.password_strength_value'] ); // not actual option

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Double authentication
	__secupress_double_auth_settings_callback( $modulenow, $settings );

	// Login protection
	__secupress_login_protection_settings_callback( $modulenow, $settings );

	// Logins blacklist
	__secupress_logins_blacklist_settings_callback( $modulenow, $settings );

	// Move Login
	__secupress_move_login_settings_callback( $modulenow, $settings, $old_settings );

	return $settings;
}


/**
 * Sanitize double authentication plugin settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_double_auth_settings_callback( $modulenow, &$settings ) {
	if ( isset( $settings['double-auth_type'] ) ) {
		switch ( $settings['double-auth_type'] ) {

			case 'googleauth':
				secupress_activate_submodule( $modulenow, 'googleauth', array( 'password', 'notif', 'emaillink' ) );
			break;

			case 'emaillink':
				secupress_activate_submodule( $modulenow, 'emaillink', array( 'password', 'notif', 'googleauth' ) );
			break;

			default:
				secupress_deactivate_submodule( $modulenow, array( 'password', 'notif', 'emaillink', 'googleauth' ) );
			break;
		}

		if ( 'password' != $settings['double-auth_type'] ) {
			$settings['double-auth_password'] = '';
		}
	}

	secupress_manage_affected_roles( $settings, 'double-auth' );
}


/**
 * Sanitize login protection plugin settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_login_protection_settings_callback( $modulenow, &$settings ) {
	if ( isset( $settings['login-protection_type'] ) ) {
		secupress_manage_submodule( $modulenow, 'bannonexistsuser', in_array( 'bannonexistsuser', $settings['login-protection_type'] ) );

		secupress_manage_submodule( $modulenow, 'limitloginattempts', in_array( 'limitloginattempts', $settings['login-protection_type'] ) );

		secupress_manage_submodule( $modulenow, 'nonlogintimeslot', in_array( 'nonlogintimeslot', $settings['login-protection_type'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'ooc', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	$settings['login-protection_number_attempts']  = isset( $settings['login-protection_number_attempts'] )  ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']         = isset( $settings['login-protection_time_ban'] )         ? secupress_validate_range( $settings['login-protection_time_ban'], 1, 60, 5 )         : 5;
	$settings['login-protection_nonlogintimeslot'] = isset( $settings['login-protection_nonlogintimeslot'] ) ? $settings['login-protection_nonlogintimeslot'] : array();
	$settings['login-protection_nonlogintimeslot']['from_hour']   = isset( $settings['login-protection_nonlogintimeslot']['from_hour'] )   ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['from_hour'], 0, 23, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['from_minute'] = isset( $settings['login-protection_nonlogintimeslot']['from_minute'] ) && in_array( $settings['login-protection_nonlogintimeslot']['from_minute'], array( '0', '15', '30', '45' ) ) ? (int) $settings['login-protection_nonlogintimeslot']['from_minute'] : 0;
	$settings['login-protection_nonlogintimeslot']['to_hour']     = isset( $settings['login-protection_nonlogintimeslot']['to_hour'] )     ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['to_hour'], 0, 23, 0 )   : 0;
	$settings['login-protection_nonlogintimeslot']['to_minute']   = isset( $settings['login-protection_nonlogintimeslot']['to_minute'] )   && in_array( $settings['login-protection_nonlogintimeslot']['to_minute'], array( '0', '15', '30', '45' ) )   ? (int) $settings['login-protection_nonlogintimeslot']['to_minute']   : 0;

	secupress_manage_submodule( $modulenow, 'login-captcha', isset( $settings['captcha_type'] ) );
}


/**
 * Sanitize and validate logins blacklist plugin settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_logins_blacklist_settings_callback( $modulenow, &$settings ) {
	// Usernames list.
	if ( isset( $settings['blacklist-logins_list'] ) && '' !== $settings['blacklist-logins_list'] ) {
		// Sanitization, validation.
		$list   = mb_strtolower( $settings['blacklist-logins_list'] );
		$list   = explode( "\n", $list );
		$strict = array_fill( 0, count( $list ) - 1, true );
		$list   = array_map( 'sanitize_user', $list, $strict );
		$list   = array_unique( $list );
		natcasesort( $list );
		$list   = implode( "\n", $list );

		while ( strpos( $list, "\n\n" ) !== false ) {
			$list = str_replace( "\n\n", "\n", $list );
		}

		$settings['blacklist-logins_list'] = trim( $list );
	}

	if ( ! isset( $settings['blacklist-logins_list'] ) || '' === $settings['blacklist-logins_list'] ) {
		// No empty list.
		$settings['blacklist-logins_list'] = secupress_blacklist_logins_list_default_string();
	}

	// Activate or deactivate plugin.
	secupress_manage_submodule( $modulenow, 'blacklist-logins', ! empty( $settings['blacklist-logins_activated'] ) );
	unset( $settings['blacklist-logins_activated'] );
}


/**
 * Sanitize and validate Move Login plugin settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow    Current module.
 * @param (array)  $settings     The module settings, passed by reference.
 * @param (array)  $old_settings The module previous settings.
 */
function __secupress_move_login_settings_callback( $modulenow, &$settings, $old_settings ) {
	// Slugs.
	$slugs     = secupress_move_login_slug_labels();
	// Handle forbidden slugs and duplicates.
	$errors    = array( 'forbidden' => array(), 'duplicates' => array() );
	// `postpass`, `retrievepassword` and `rp` are forbidden if they are not customizable.
	$forbidden = array( 'postpass' => 1, 'retrievepassword' => 1, 'rp' => 1 );
	$forbidden = array_diff_key( $forbidden, $slugs );
	$dones     = array();

	foreach ( $slugs as $default_slug => $label ) {
		$option_name = 'move-login_slug-' . $default_slug;

		// Build a fallback slug. Try the old value first.
		$fallback_slug = ! empty( $old_settings[ $option_name ] ) ? sanitize_title( $old_settings[ $option_name ] ) : '';
		// Then fallback to the default value.
		if ( ! $fallback_slug || isset( $forbidden[ $fallback_slug ] ) || isset( $dones[ $fallback_slug ] ) ) {
			$fallback_slug = $default_slug;
		}
		// Last chance, add an increment.
		if ( isset( $forbidden[ $fallback_slug ] ) || isset( $dones[ $fallback_slug ] ) ) {
			$i = 1;
			while ( isset( $forbidden[ $fallback_slug . $i ] ) || isset( $dones[ $fallback_slug . $i ] ) ) {
				++$i;
			}
			$fallback_slug .= $i;
		}

		// Sanitize the value provided.
		$new_slug = ! empty( $settings[ $option_name ] ) ? sanitize_title( $settings[ $option_name ] ) : '';

		if ( ! $new_slug ) {
			// Sanitization did its job til the end, or the field was empty.
			$new_slug = $fallback_slug;
		} else {
			// Validation.
			// Test for forbidden slugs.
			if ( isset( $forbidden[ $new_slug ] ) ) {
				$errors['forbidden'][] = $new_slug;
				$new_slug = $fallback_slug;
			}
			// Test for duplicates.
			elseif ( isset( $dones[ $new_slug ] ) ) {
				$errors['duplicates'][] = $new_slug;
				$new_slug = $fallback_slug;
			}
		}

		$dones[ $new_slug ]       = 1;
		$settings[ $option_name ] = $new_slug;
	}

	// Access to `wp-login.php`.
	$wp_login_actions = secupress_move_login_wplogin_access_labels();
	$settings['move-login_wp-login-access'] = isset( $settings['move-login_wp-login-access'], $wp_login_actions[ $settings['move-login_wp-login-access'] ] ) ? $settings['move-login_wp-login-access'] : 'error';

	// Access to `wp-admin`.
	$admin_actions = secupress_move_login_admin_access_labels();
	$settings['move-login_admin-access'] = isset( $settings['move-login_admin-access'], $wp_login_actions[ $settings['move-login_admin-access'] ] ) ? $settings['move-login_admin-access'] : 'redir-login';

	// Handle validation errors.
	$errors['forbidden']  = array_unique( $errors['forbidden'] );
	$errors['duplicates'] = array_unique( $errors['duplicates'] );

	if ( $nbr_forbidden = count( $errors['forbidden'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= sprintf( _n( 'The slug %s is forbidden.', 'The slugs %s are forbidden.', $nbr_forbidden, 'secupress' ), wp_sprintf( '<code>%l</code>', $errors['forbidden'] ) );
		add_settings_error( "secupress_{$modulenow}_settings", 'forbidden-slugs', $message, 'error' );
	}
	if ( ! empty( $errors['duplicates'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'The links can\'t have the same slugs.', 'sf-move-login' );
		add_settings_error( "secupress_{$modulenow}_settings", 'duplicate-slugs', $message, 'error' );
	}

	// Activate or deactivate plugin.
	secupress_manage_submodule( $modulenow, 'move-login', ! empty( $settings['move-login_activated'] ) );
	unset( $settings['move-login_activated'], $settings['move-login_rules'] );
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

/*
 * Create default option on install.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */

add_action( 'wp_secupress_first_install', '__secupress_install_users_login_module' );

function __secupress_install_users_login_module( $module ) {
	if ( 'all' === $module || 'users-login' === $module ) {
		$values = array(
			'double-auth_type'      => '-1',
			'blacklist-logins_list' => secupress_blacklist_logins_list_default_string(),
			//// pas fini
		);
		secupress_update_module_options( $values, 'users-login' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DEFAULT VALUES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Logins blacklist: return the default usernames blacklist.
 *
 * @since 1.0
 *
 * @param (string) $glue If set, the returned list will be imploded using this parameter as glue.
 *
 * @return (array|string) Return an array, or a string if the `$glue` parameter is set.
 */
function secupress_blacklist_logins_list_default( $glue = null ) {
	$list = array(
		'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
		'backup', 'banner', 'banners', 'bin', 'billing', 'blog', 'blogs', 'board', 'bot', 'bots', 'business',
		'chat', 'cache', 'cadastro', 'calendar', 'campaign', 'careers', 'cdn', 'cgi', 'client', 'cliente', 'code', 'comercial', 'compare', 'config', 'connect', 'contact', 'contest', 'create', 'code', 'compras', 'css',
		'dashboard', 'data', 'db', 'design', 'delete', 'demo', 'design', 'designer', 'dev', 'devel', 'dir', 'directory', 'doc', 'documentation', 'docs', 'domain', 'download', 'downloads',
		'edit', 'editor', 'email', 'ecommerce',
		'forum', 'forums', 'faq', 'favorite', 'feed', 'feedback', 'flog', 'follow', 'file', 'files', 'free', 'ftp',
		'gadget', 'gadgets', 'games', 'guest', 'group', 'groups',
		'help', 'home', 'homepage', 'host', 'hosting', 'hostname', 'htm', 'html', 'http', 'httpd', 'https', 'hpg',
		'info', 'information', 'image', 'img', 'images', 'imap', 'index', 'invite', 'intranet', 'indice', 'ipad', 'iphone', 'irc',
		'java', 'javascript', 'job', 'jobs', 'js',
		'knowledgebase',
		'log', 'login', 'logs', 'logout', 'list', 'lists',
		'mail', 'mail1', 'mail2', 'mail3', 'mail4', 'mail5', 'mailer', 'mailing', 'mx', 'manager', 'marketing', 'master', 'me', 'media', 'message', 'microblog', 'microblogs', 'mine', 'mp3', 'msg', 'msn', 'mysql', 'messenger', 'mob', 'mobile', 'movie', 'movies', 'music', 'musicas', 'my',
		'name', 'named', 'net', 'network', 'new', 'news', 'newsletter', 'nick', 'nickname', 'notes', 'noticias', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9',
		'old', 'online', 'operator', 'order', 'orders',
		'page', 'pager', 'pages', 'panel', 'password', 'perl', 'pic', 'pics', 'photo', 'photos', 'photoalbum', 'php', 'plugin', 'plugins', 'pop', 'pop3', 'post', 'postmaster', 'postfix', 'posts', 'private', 'profile', 'project', 'projects', 'promo', 'pub', 'public', 'python',
		'random', 'register', 'registration', 'root', 'ruby', 'rss',
		'sale', 'sales', 'sample', 'samples', 'script', 'scripts', 'secure', 'send', 'service', 's'.'e'.'x', 'shop', 'sql', 'signup', 'signin', 'search', 'security', 'settings', 'setting', 'setup', 'site', 'sites', 'sitemap', 'smtp', 'soporte', 'ssh', 'stage', 'staging', 'start', 'subscribe', 'subdomain', 'suporte', 'support', 'stat', 'static', 'stats', 'status', 'store', 'stores', 'system',
		'tablet', 'tablets', 'tech', 'telnet', 'test', 'test1', 'test2', 'test3', 'teste', 'tests', 'theme', 'themes', 'tmp', 'todo', 'task', 'tasks', 'tools', 'tv', 'talk',
		'update', 'upload', 'url', 'user', 'username', 'usuario', 'usage',
		'vendas', 'video', 'videos', 'visitor',
		'win', 'ww', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www9', 'www9', 'wwww', 'wws', 'wwws', 'web', 'webmail', 'website', 'websites', 'webmaster', 'workshop',
		'xxx', 'xpg',
		'you',
	);

	return isset( $glue ) ? implode( $glue, $list ) : $list;
}


/*
 * Logins blacklist: return the default usernames blacklist as a string, with a `\n` caracter as separator.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_blacklist_logins_list_default_string() {
	return secupress_blacklist_logins_list_default( "\n" );
}


/*
 * Move Login: return the list of customizable login actions.
 *
 * @since 1.0
 *
 * @return (array) Return an array with the action names as keys and field labels as values.
 */
function secupress_move_login_slug_labels() {
	$labels = array(
		'login'        => __( 'Log in' ),
		'logout'       => __( 'Log out' ),
		'register'     => __( 'Register' ),
		'lostpassword' => __( 'Lost Password' ),
		'resetpass'    => __( 'Password Reset' ),
	);

	/**
	 * Add custom actions to the list of customizable actions.
	 *
	 * @since 1.0
	 *
	 * @param (array) An array with the action names as keys and field labels as values.
	*/
	$new_slugs = apply_filters( 'sfml_additional_slugs', array() );

	if ( $new_slugs && is_array( $new_slugs ) ) {
		$new_slugs = array_diff_key( $new_slugs, $labels );
		$labels    = array_merge( $labels, $new_slugs );
	}

	return $labels;
}


/*
 * Move Login: return the list of available actions to perform when someone reaches the old login page.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_move_login_wplogin_access_labels() {
	return array(
		'error'      => __( 'Display an error message', 'secupress' ),
		'redir_404'  => __( 'Redirect to a "Page not found" error page', 'secupress' ),
		'redir_home' => __( 'Redirect to the home page', 'secupress' ),
	);
}


/*
 * Move Login: return the list of available actions to perform when a logged out user reaches the administration area.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_move_login_admin_access_labels() {
	return array(
		'redir-login' => __( 'Do nothing, redirect to the new login page', 'secupress' ),
		'error'       => __( 'Display an error message', 'secupress' ),
		'redir_404'   => __( 'Redirect to a "Page not found" error page', 'secupress' ),
		'redir_home'  => __( 'Redirect to the home page', 'secupress' ),
	);
}


/*------------------------------------------------------------------------------------------------*/
/* UTILITIES ==================================================================================== */
/*------------------------------------------------------------------------------------------------*/

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
