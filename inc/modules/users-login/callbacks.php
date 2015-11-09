<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_users_login_settings_callback( $settings ) {
	$modulenow = 'users-login';
	$settings = $settings ? $settings : array();

	// double-auth
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

	unset( $settings['temp.password_strength_value'] ); // not actual option

	if ( isset( $settings['profile_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'profile-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile-protect' );
	}
	secupress_manage_affected_roles( $settings, 'profile-protect' );

	// login-protection
	if ( isset( $settings['login-protection_type'] ) ) {
		if ( in_array( 'bannonexistsuser', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'bannonexistsuser' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'bannonexistsuser' );
		}
		if ( in_array( 'limitloginattempts', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'limitloginattempts' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'limitloginattempts' );
		}
		if ( in_array( 'nonlogintimeslot', $settings['login-protection_type'] ) ) {
			secupress_activate_submodule( $modulenow, 'nonlogintimeslot' );
		} else {
			secupress_deactivate_submodule( $modulenow, 'nonlogintimeslot' );
		}
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bannonexistsuser', 'ooc', 'limitloginattempts', 'nonlogintimeslot' ) );
	}

	$settings['login-protection_number_attempts'] = isset( $settings['login-protection_number_attempts'] ) ? secupress_validate_range( $settings['login-protection_number_attempts'], 3, 99, 10 ) : 10;
	$settings['login-protection_time_ban']        = isset( $settings['login-protection_time_ban'] )        ? secupress_validate_range( $settings['login-protection_time_ban'], 1, 60, 5 )         : 5;
	if ( ! isset( $settings['login-protection_nonlogintimeslot'] ) ) {
		$settings['login-protection_nonlogintimeslot'] = array();
	}
	$settings['login-protection_nonlogintimeslot']['from_hour']   = isset( $settings['login-protection_nonlogintimeslot']['from_hour'] )   ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['from_hour'], 0, 23, 0 ) : 0;
	$settings['login-protection_nonlogintimeslot']['from_minute'] = isset( $settings['login-protection_nonlogintimeslot']['from_minute'] ) && in_array( $settings['login-protection_nonlogintimeslot']['from_minute'], array( '0', '15', '30', '45' ) ) ? (int) $settings['login-protection_nonlogintimeslot']['from_minute'] : 0;
	$settings['login-protection_nonlogintimeslot']['to_hour']     = isset( $settings['login-protection_nonlogintimeslot']['to_hour'] )     ? secupress_validate_range( $settings['login-protection_nonlogintimeslot']['to_hour'], 0, 23, 0 )   : 0;
	$settings['login-protection_nonlogintimeslot']['to_minute']   = isset( $settings['login-protection_nonlogintimeslot']['to_minute'] )   && in_array( $settings['login-protection_nonlogintimeslot']['to_minute'], array( '0', '15', '30', '45' ) )   ? (int) $settings['login-protection_nonlogintimeslot']['to_minute']   : 0;

	if ( isset( $settings['captcha_type'] ) ) {
		secupress_activate_submodule( $modulenow, 'login-captcha' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'login-captcha' );
	}

	// Logins blacklist.
	$settings['bad-logins_blacklist-logins'] = ! empty( $settings['bad-logins_blacklist-logins'] ) ? 1 : 0;

	if ( isset( $settings['bad-logins_blacklist-logins-list'] ) && '' !== $settings['bad-logins_blacklist-logins-list'] ) {
		// Sanitization, validation.
		$list   = explode( "\n", $settings['bad-logins_blacklist-logins-list'] );
		$strict = array_fill( 0, count( $list ) - 1, true );
		$list   = array_map( 'sanitize_user', $list, $strict );
		$list   = array_unique( $list );
		natcasesort( $list );
		$list   = implode( "\n", $list );

		while ( strpos( $list, "\n\n" ) !== false ) {
			$list = str_replace( "\n\n", "\n", $list );
		}

		$settings['bad-logins_blacklist-logins-list'] = trim( $list );
	}

	if ( ! isset( $settings['bad-logins_blacklist-logins-list'] ) || '' === $settings['bad-logins_blacklist-logins-list'] ) {
		// No empty list.
		$settings['bad-logins_blacklist-logins-list'] = secupress_blacklist_logins_list_default_string();
	}

	if ( $settings['bad-logins_blacklist-logins'] ) {
		secupress_activate_submodule( $modulenow, 'logins-blacklist' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'logins-blacklist' );
	}

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

// Create default option on install.

add_action( 'wp_secupress_first_install', '__secupress_install_users_login_module' );

function __secupress_install_users_login_module( $module = 'all' ) {
	if ( 'all' === $module || 'users-login' === $module ) {
		update_option( 'secupress_users-login_settings', array(
			'double-auth_type'                 => '-1',
			'bad-logins_blacklist-logins-list' => secupress_blacklist_logins_list_default_string(),
			//// pas fini
		) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DEFAULT VALUES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

function secupress_blacklist_logins_list_default( $glue = null ) {
	$list = array(
		'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'admin', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
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


function secupress_blacklist_logins_list_default_string() {
	return secupress_blacklist_logins_list_default( "\n" );
}


/*------------------------------------------------------------------------------------------------*/
/* UTILITIES ==================================================================================== */
/*------------------------------------------------------------------------------------------------*/

function secupress_blacklist_logins_allowed_characters( $wrap = false ) {
	$allowed = array( 'A-Z', 'a-z', '0-9', '(space)', '_', '.', '-', '@', );
	if ( $wrap ) {
		foreach ( $allowed as $i => $char ) {
			$allowed[ $i ] = '<code>' . $char . '</code>';
		}
	}
	$allowed = wp_sprintf_l( '%l', $allowed );

	return sprintf( __( 'Allowed characters: %s.', 'secupress' ), $allowed );
}
