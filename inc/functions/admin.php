<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get SecuPress scanner counter(s)
 *
 * @since 1.0
 */
function secupress_get_scanner_counts( $type = '' ) {
	$tests_by_status = secupress_get_tests();
	$scanners        = secupress_get_scanners();
	$empty_statuses  = array( 'good' => 0, 'warning' => 0, 'bad' => 0 );
	$scanners_count  = ! empty( $scanners ) ? array_count_values( wp_list_pluck( $scanners, 'status' ) ) : array();
	$counts          = array_merge( $empty_statuses, $scanners_count );

	$counts['notscannedyet'] = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] ) - array_sum( $counts );
	$counts['total']         = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] );
	$percent                 = floor( $counts['good'] * 100 / $counts['total'] );

	if ( $percent >= 90 ) {
		$counts['grade'] = 'A';
	} elseif ( $percent >= 80 ) {
		$counts['grade'] = 'B';
	} elseif ( $percent >= 70 ) {
		$counts['grade'] = 'C';
	} elseif ( $percent >= 60 ) {
		$counts['grade'] = 'D';
	} elseif ( $percent >= 50 ) {
		$counts['grade'] = 'E';
	} else {
		$counts['grade'] = 'F';
	}

	if ( isset( $counts[ $type ] ) ) {
		return $counts[ $type ];
	}

	return $counts;
}


/**
 * Add SecuPress informations into USER_AGENT
 *
 * @since 1.0
 */
function secupress_user_agent( $user_agent ) {

	$bonus  = ! secupress_is_white_label() ? '' : '*';
	$bonus .= ! secupress_get_option( 'do_beta' ) ? '' : '+';
	$new_ua = sprintf( '%s;SecuPress|%s%s|%s|;', $user_agent, SECUPRESS_VERSION, $bonus, esc_url( home_url() ) );

	return $new_ua;
}


/**
 * Renew all boxes for everyone if $uid is missing
 *
 * @since 1.0
 *
 * @param (int|null)$uid : a User id, can be null, null = all users
 * @param (string|array)$keep_this : which box have to be kept
 * @return void
 */
function secupress_renew_all_boxes( $uid = null, $keep_this = array() ) {
	// Delete a user meta for 1 user or all at a time
	delete_metadata( 'user', $uid, 'secupress_boxes', null == $uid );

	// $keep_this works only for the current user
	if ( ! empty( $keep_this ) && null != $uid ) {
		if ( is_array( $keep_this ) ) {
			foreach ( $keep_this as $kt ) {
				secupress_dismiss_box( $kt );
			}
		} else {
			secupress_dismiss_box( $keep_this );
		}
	}
}


/**
 * Renew a dismissed error box admin side
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_renew_box( $function, $uid = 0 ) {
	global $current_user;

	$uid    = $uid == 0 ? $current_user->ID : $uid;
	$actual = get_user_meta( $uid, 'secupress_boxes', true );

	if ( $actual && false !== array_search( $function, $actual ) ) {
		unset( $actual[ array_search( $function, $actual ) ] );
		update_user_meta( $uid, 'secupress_boxes', $actual );
	}
}


/**
 * Dismissed 1 box, wrapper of rocket_dismiss_boxes()
 *
 * @since 1.0
 *
 * @return void
 */
function secupress_dismiss_box( $function ) {
	// secupress_dismiss_boxes(
	//  array(
	//      'box'      => $function,
	//      '_wpnonce' => wp_create_nonce( 'secupress_ignore_' . $function ),
	//      'action'   => 'secupress_ignore'
	//  )
	// );
}


/**
 * Is this version White Labeled?
 *
 * @return string
 * @since 1.0
 */
function secupress_is_white_label() {
	$names   = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );
	$options = '';

	foreach ( $names as $value ) {
		$options .= ! is_array( secupress_get_option( $value ) ) ? secupress_get_option( $value ) : reset( ( secupress_get_option( $value ) ) );
	}

	return false; ////
	return 'a509cac94e0cd8238b250074fe802b90' != md5( $options ); ////
}


/**
 * Reset white label options
 *
 * @since 1.0
 * @return void
 */
function secupress_reset_white_label_values( $hack_post ) {
	// White Label default values - !!! DO NOT TRANSLATE !!!
	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$options['wl_plugin_name'] = 'SecuPress';
	$options['wl_plugin_slug'] = 'secupress';
	$options['wl_plugin_URI']  = 'http://secupress.me';
	$options['wl_description'] = array( 'The best WordPress security plugin.' );
	$options['wl_author']      = 'WP Media';
	$options['wl_author_URI']  = 'http://secupress.me';

	if ( $hack_post ) {
		// hack $_POST to force refresh of files, sorry
		$_POST['page'] = 'secupress';
	}

	update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
}


/**
 * Create a unique id for some secupress options and functions
 *
 * @since 1.0
 * @return string
 */
function secupress_create_uniqid() {
	return str_replace( '.', '', uniqid( '', true ) );
}


/**
 * Die with SecuPress format
 *
 * @since 1.0
 */
function secupress_die( $message = '', $title = '', $args = array() ) {
	$has_p   = strpos( $message, '<p>' ) !== false;
	$message = ( $has_p ? '' : '<p>' ) . $message . ( $has_p ? '' : '</p>' );
	$url     = secupress_get_current_url( 'raw' );

	/**
	 * Fires right before `wp_die()`.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $_SERVER The superglobal var.
	 */
	do_action( 'secupress.before.die', $message, $url, $_SERVER );

	wp_die( '<h1>' . SECUPRESS_PLUGIN_NAME . '</h1>' . $message, $title, $args );
}


/**
 * Block a request and die with more informations
 *
 * @param $module string The related module
 * @param $args array|int|string Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message
 * $args can be used only for the "code" or "content" or both using an array
 *
 * @since 1.0
 * @return string
 */
function secupress_block( $module, $args = array( 'code' => 403 ) ) {

	if ( is_int( $args ) ) {
		$args = array( 'code' => $args );
	} elseif ( is_string( $args ) ) {
		$args = array( 'content' => $args );
	}

	$args = wp_parse_args( $args, array( 'code' => 403, 'content' => '' ) );

	do_action( 'secupress.block.' . $module, secupress_get_ip(), $args );
	do_action( 'secupress.block', $module, secupress_get_ip(), $args );

	$module = ucwords( str_replace( '-', ' ', $module ) );
	$module = preg_replace( '/[^0-9A-Z]/', '', $module );

	status_header( $args['code'] );
	$title     = $args['code']  . ' ' . get_status_header_desc( $args['code'] );
	$title_fmt = '<h4>' . $title . '</h4>';
	if ( ! $args['content'] ) {
		$content = '<p>' . __( 'You are not allowed to access the requested page.', 'secupress' ) . '</p>';
	} else {
		$content = '<p>' . $args['content'] . '</p>';
	}
	$details   = '<h4>' . __( 'Logged Details:', 'secupress' ) . '</h4><p>';
	$details  .= sprintf( __( 'Your IP: %s', 'secupress' ), secupress_get_ip() ) . '<br>';
	$details  .= sprintf( __( 'Time: %s', 'secupress' ), date_i18n( __( 'F j, Y g:i a' ) ) ) . '<br>';
	$details  .= sprintf( __( 'Block ID: %s', 'secupress' ), $module ) . '</p>';
	secupress_die( $title_fmt . $content . $details, $title, array( 'response', $args['code'] ) );
}


/**
 * Display a small page, usually used to block a user until this user provides some info.
 *
 * @since 1.0
 *
 * @param (string) $title   The title tag content.
 * @param (string) $content The page content.
 * @param (array)  $args    Some more data:
 *                 - $head  Content to display in the document's head.
 */
function secupress_action_page( $title, $content, $args = array() ) {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		return;
	}

	$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version = $suffix ? SECUPRESS_VERSION : time();

	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php echo strip_tags( $title ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<link href="<?php echo SECUPRESS_ADMIN_CSS_URL . 'secupress-action-page' . $suffix . '.css?ver=' . $version; ?>" media="all" rel="stylesheet" />
		<?php echo ! empty( $args['head'] ) ? $args['head'] : ''; ?>
	</head>
	<body>
		<?php echo $content; ?>
	</body>
</html><?php
	die();
}


function secupress_deactivate_submodule( $module, $plugins, $args = array() ) {
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( ! is_array( $plugins ) ) {
		$plugins = (array) $plugins;
	}

	foreach ( $plugins as $plugin ) {
		$plugin_file = sanitize_key( $plugin );

		if ( $active_plugins && isset( $active_plugins[ $module ] ) && in_array_deep( $plugin_file, $active_plugins ) ) {

			$key = array_search( $plugin_file, $active_plugins[ $module ] );

			if ( false !== $key ) {
				unset( $active_plugins[ $module ][ $key ] );

				update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
				secupress_add_module_notice( $module, $plugin_file, 'deactivation' );

				do_action( 'secupress_deactivate_plugin_' . $plugin_file, $args );

				do_action( 'secupress_deactivate_plugin', $plugin_file, $args );
			}
		}
	}
}


function secupress_activate_module( $module, $settings ) { //// rename this, it finally does not ativate any module but just set the correct settings.
	$modules  = secupress_get_modules();
	$callback = str_replace( '-', '_', $module );

	if ( ! function_exists( "__secupress_{$callback}_settings_callback" ) || ! isset( $modules[ $module ] ) ) {
		secupress_die( sprintf( __( 'Unknown Module %s', 'secupress' ), esc_html( $module ) ) );
	}

	$module_options = get_site_option( "secupress_{$module}_settings" );
	$module_options = array_merge( array_filter( (array) $module_options ), $settings );

	call_user_func( "__secupress_{$callback}_settings_callback", $module_options );

	update_site_option( "secupress_{$module}_settings", $module_options );

}


function secupress_activate_submodule( $module, $plugin, $incompatibles_modules = array() ) { //// add the possiblity to activate it in "silent mode" (from a scanner fix and not from a user checkbox)?
	$plugin_file    = sanitize_key( $plugin );
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
	$file_path      = SECUPRESS_MODULES_PATH . $module . '/plugins/' . $plugin_file . '.php';

	if ( ! file_exists( $file_path ) ) {
		return false;
	}

	if ( ! in_array_deep( $plugin_file, $active_plugins ) ) {
		if ( ! empty( $incompatibles_modules ) ) {
			secupress_deactivate_submodule( $module, $incompatibles_modules );
		}

		$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
		$active_plugins[ $module ][] = $plugin_file;

		update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
		require_once( $file_path );
		secupress_add_module_notice( $module, $plugin_file, 'activation' );

		do_action( 'secupress_activate_plugin_' . $plugin_file );

		do_action( 'secupress_activate_plugin', $plugin_file );

		return true;
	}

	return false;
}


function secupress_manage_submodule( $module, $plugin, $activate ) {
	if ( $activate ) {
		secupress_activate_submodule( $module, $plugin );
	} else {
		secupress_deactivate_submodule( $module, $plugin );
	}
}


function secupress_add_module_notice( $module, $submodule, $action ) {
	global $current_user;

	$transient_name = "secupress_module_{$action}_{$current_user->ID}";
	$current        = get_site_transient( $transient_name );
	$submodule_data = secupress_get_module_data( $module , $submodule );
	$current[]      = $submodule_data['Name'];

	set_site_transient( $transient_name, $current );

	do_action( 'module_notice_' . $action, $module, $submodule );
}


function secupress_get_module_data( $module, $submodule ) {
	$default_headers = array(
		'Name'        => 'Module Name',
		'Module'      => 'Main Module',
		'Version'     => 'Version',
		'Description' => 'Description',
		'Author'      => 'Author',
	);

	$file = SECUPRESS_MODULES_PATH . $module . '/plugins/' . $submodule . '.php';

	if ( file_exists( $file ) ) {
		return get_file_data( $file, $default_headers, 'module' );
	}

	return array();
}


function secupress_generate_key() {
	$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	$key = '';
	for ( $i = 0; $i < 16; $i++ ) {
		$key .= $chars[ wp_rand( 0, 31 ) ];
	}

	return $key;
}


function secupress_generate_backupcodes() {
	$keys = array();

	for ( $k = 1; $k <= 10; $k++ ) { // 10 codes
		$max = 99999999;
		$keys[ $k ] = str_pad( wp_rand( floor( $max / 10 ), $max ), strlen( (string) $max ), '0', STR_PAD_RIGHT );
	}

	return $keys;
}


function secupress_generate_password( $length = 12, $args = array() ) {
	$defaults = array( 'min' => true, 'maj' => true, 'num' => true, 'special' => false, 'extra' => false, 'custom' => '' );
	$args     = wp_parse_args( $args, $defaults );
	$chars    = array();

	$chars['min']     = 'abcdefghijklmnopqrstuvwxyz';
	$chars['maj']     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$chars['num']     = '0123456789';
	$chars['special'] = '!@#$%^&*()';
	$chars['extra']   = '-_ []{}<>~`+=,.;:/?|';
	$chars['custom']  = $args['custom'];

	$usable_chars = '';

	foreach ( $args as $key => $arg ) {
		$usable_chars .= $args[ $key ] ? $chars[ $key ] : '';
	}

	$password = '';

	for ( $i = 0; $i < $length; $i++ ) {
		$password .= substr( $usable_chars, wp_rand( 0, strlen( $usable_chars ) - 1 ), 1 );
	}

	return $password;
}


function secupress_manage_affected_roles( &$settings, $plugin ) {
	static $roles;

	if ( ! isset( $roles ) ) {
		$roles = new WP_Roles();
		$roles = $roles->get_names();
		$roles = array_flip( $roles );
		$roles = array_combine( $roles, $roles );
	}

	if ( empty( $settings[ $plugin . '_affected_role' ] ) || ! is_array( $settings[ $plugin . '_affected_role' ] ) ) {
		$settings[ $plugin . '_affected_role' ] = $roles;
	} else {
		$settings[ $plugin . '_affected_role' ] = array_diff( $roles, $settings[ $plugin . '_affected_role' ] );
	}
}


function secupress_get_ip() { //// find the best order
	$keys = array(
		'HTTP_CF_CONNECTING_IP', // CF = CloudFlare
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	);

	foreach ( $keys as $key ) {
		if ( array_key_exists( $key, $_SERVER ) ) {
			$ip = explode( ',', $_SERVER[ $key ] );
			$ip = end( $ip );

			if ( false !== filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				// return apply_filters( 'secupress_get_ip', $ip ); //// maybe not
				return $ip;
			}
		}
	}

	return apply_filters( 'secupress_default_ip', '0.0.0.0' );
}


function secupress_ban_ip( $IP = null, $die = true ) {
	$login_protection_time_ban = (int) secupress_get_module_option( 'login_protection_time_ban', 5, 'users_login' );
	$IP                        = $IP ? $IP : secupress_get_ip();
	$ban_ips                   = get_site_option( SECUPRESS_BAN_IP );

	if ( ! is_array( $ban_ips ) ) {
		$ban_ips = array();
	}

	$ban_ips[ $IP ] = time();

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/**
	 * Fires once a IP is banned.
	 *
	 * @since 1.0
	 *
	 * @param (string) $IP      The IP banned.
	 * @param (array)  $ban_ips The list of IPs banned (keys) and the time they were banned (values).
	 */
	do_action( 'secupress.ip_banned', $IP, $ban_ips );

	if ( apply_filters( 'write_ban_in_htaccess', true ) ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	if ( $die ) {
		secupress_die( sprintf(
			_n( 'Your IP address %1$s has been banned for %2$s minute, please do not retry until then.', 'Your IP address %1$s has been banned for %2$s minutes, please do not retry until then.', $login_protection_time_ban, 'secupress' ),
			'<code>' . esc_html( $IP ) . '</code>',
			'<strong>' . number_format_i18n( $login_protection_time_ban ) . '</strong>'
		) );
	}
}
