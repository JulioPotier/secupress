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

	switch ( $percent ) {
		case $percent >= 90: $counts['grade'] = 'A'; break;
		case $percent >= 80: $counts['grade'] = 'B'; break;
		case $percent >= 70: $counts['grade'] = 'C'; break;
		case $percent >= 60: $counts['grade'] = 'D'; break;
		case $percent >= 50: $counts['grade'] = 'E'; break;
		default: $counts['grade'] = 'F'; break;
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
 *
 * @return void
 */
function secupress_reset_white_label_values( $hack_post ) {
	// White Label default values - !!! DO NOT TRANSLATE !!!
	$options = get_option( SECUPRESS_SETTINGS_SLUG );
	$options['wl_plugin_name'] = 'SecuPress';
	$options['wl_plugin_slug'] = 'secupress';
	$options['wl_plugin_URI']  = 'http://www.secupress.fr';
	$options['wl_description'] = array( 'The best WordPress security plugin.' );
	$options['wl_author']      = 'WP Media';
	$options['wl_author_URI']  = 'http://www.secupress.fr';

	if ( $hack_post ) {
		// hack $_POST to force refresh of files, sorry
		$_POST['page'] = 'secupress';
	}

	update_option( SECUPRESS_SETTINGS_SLUG, $options );
}


/**
 * Create a unique id for some secupress options and functions
 *
 * @since 1.0
 */
function create_secupress_uniqid() {
	return str_replace( '.', '', uniqid( '', true ) );
}


function secupress_die( $message = '', $title = '', $args = array() ) {
	wp_die( '<h1>' . SECUPRESS_PLUGIN_NAME . '</h1><p>' . $message . '</p>', $title, $args );
}


function do_secupress_settings_sections( $page ) {
	echo '<div class="secublock">';
		do_settings_sections( $page );
	echo '</div>';
}


function __secupress_get_hidden_classes( $classes ) {
	$output = 'hide-if-js block-hidden ' . $classes;
	return $output;
}


function secupress_deactivate_submodule( $module, $plugins ) {
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
				do_action( 'secupress_deactivate_plugin_' . $plugin_file );
			}
		}
	}
}

function secupress_activate_module( $module, $settings ) {
	$modules = secupress_get_modules();

	if ( ! function_exists( "__secupress_{$module}_settings_callback" ) || ! isset( $modules[ $module ] ) ) {
		secupress_die( sprintf( __( 'Unknow Module %s', 'secupress' ), esc_html( $module ) ) );
	}

	$module_options = get_option( "secupress_{$module}_settings" );
	$module_options = array_merge( $module_options, $settings );

	call_user_func( "__secupress_{$module}_settings_callback", $module_options );

	update_option( "secupress_{$module}_settings", $module_options );

	if ( ! defined( 'DOING_AJAX' ) ) {
		__secupress_scanner_ajax( $module );
	}
}

function secupress_activate_submodule( $module, $plugin, $incompatibles_modules = array() ) {
	$plugin_file    = sanitize_key( $plugin );
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( ! in_array_deep( $plugin_file, $active_plugins ) ) {
		if ( ! empty( $incompatibles_modules ) ) {
			secupress_deactivate_submodule( $module, $incompatibles_modules );
		}

		$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
		$active_plugins[ $module ][] = $plugin_file;

		update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
		require_once( SECUPRESS_MODULES_PATH . $module . '/plugins/' . $plugin_file . '.php' );
		secupress_add_module_notice( $module, $plugin_file, 'activation' );

		do_action( 'secupress_activate_plugin_' . $plugin_file );
	}
}


function secupress_add_module_notice( $module, $submodule, $action ) {
	global $current_user;

	$current        = get_site_transient( "secupress_module_{$action}_{$current_user->ID}" );
	$submodule_data = secupress_get_module_data( $module , $submodule );
	$current[]      = $submodule_data['Name'];

	set_site_transient( "secupress_module_{$action}_{$current_user->ID}", $current );

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


function secupress_load_settings( $module, $plugin ) {
	$plugin_file = SECUPRESS_MODULES_PATH . sanitize_key( $module ) . '/settings/' . sanitize_key( $plugin ) . '.php';

	if ( file_exists( $plugin_file ) ) {
		require( $plugin_file );
	}
}


function secupress_manage_affected_roles( &$settings, $pluginnow ) {
	if ( isset( $settings[ 'hidden_' . $pluginnow . '_affected_role' ] ) ) {
		$settings[ $pluginnow . '_affected_role' ] = array_diff( $settings[ 'hidden_' . $pluginnow . '_affected_role' ], $settings[ $pluginnow . '_affected_role' ] );
	}

	unset( $settings[ 'hidden_' . $pluginnow . '_affected_role' ] ); // not actual option
}


function secupress_get_ip() {
	$keys = array(
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	);

	foreach ( $keys as $key ) {
		if ( array_key_exists( $key, $_SERVER ) ) {
			$ip = explode( ',', $_SERVER[ $key ] );
			$ip = end( $ip );

			if ( false !== filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return apply_filters( 'secupress_get_ip', $ip );
			}
		}
	}

	return apply_filters( 'secupress_default_ip', '0.0.0.0' );
}


function secupress_ban_ip( $IP = null, $die = true ) {
	$bad_logins_time_ban = secupress_get_module_option( 'bad_logins_time_ban', 5, 'users_login' );
	$IP                  = $IP ? $IP : secupress_get_ip();
	$ban_ips             = get_option( SECUPRESS_BAN_IP );

	if ( ! is_array( $ban_ips ) ) {
		$ban_ips = array();
	}

	$ban_ips[ $IP ] = time();

	update_option( SECUPRESS_BAN_IP, $ban_ips );

	if ( apply_filters( 'write_ban_in_htaccess', true ) ) {
		secupress_write_htaccess( 'ban_ip' );
	}

	if ( $die ) {
		$msg = sprintf( __( 'Your IP address %1$s have been banned for %2$d minutes, please do not retry until.', 'secupress' ), '<code>' . esc_html( $IP ) . '</code>', '<strong>' . $bad_logins_time_ban . '</strong>' );
		secupress_die( $msg );
	}
}
