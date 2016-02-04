<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ADMIN POST / AJAX CALLBACKS ================================================================== */
/*------------------------------------------------------------------------------------------------*/

// Scan callback.

add_action( 'admin_post_secupress_scanner', '__secupress_scanit_action_callback' );
add_action( 'wp_ajax_secupress_scanner',    '__secupress_scanit_action_callback' );
/**
 * Used to scan a test in scanner page.
 *
 * @since 1.0
 *
 * @return (string) json format or redirects the user.
 **/
function __secupress_scanit_action_callback() {

	if ( empty( $_GET['test'] ) || empty( $_GET['_wpnonce'] ) ) {
		secupress_admin_die();
	}

	$test_name = esc_attr( $_GET['test'] );
	$nonce     = wp_verify_nonce( $_GET['_wpnonce'], 'secupress_scanner_' . $test_name );

	if ( ! $test_name || ! $nonce ) {
		secupress_admin_die();
	}

	$for_current_site = ! empty( $_GET['for-current-site'] );
	$response = secupress_scanit( $test_name, true, $for_current_site );

/*	$times   = (array) get_site_option( SECUPRESS_SCAN_TIMES );
	$counts  = secupress_get_scanner_counts();
	$percent = floor( $counts['good'] * 100 / $counts['total'] );
	$times[] = array( 'grade' => $counts['grade'], 'percent' => $percent, 'time' => time() );
	$times   = array_filter( array_slice( $times , -5 ) );
	update_site_option( SECUPRESS_SCAN_TIMES, $times );*////

	secupress_admin_send_response_or_redirect( $response, 'scanners' );
}


/**
 * Get the result of a scan.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name.
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the scan for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 **/
function secupress_scanit( $test_name, $format_response = false, $for_current_site = false ) {
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$response = $classname::get_instance()->for_current_site( $for_current_site )->scan();
			/*
			 * $response is an array that MUST contain "status" and MUST contain "msgs".
			 */
		ob_end_flush();
	}

	if ( $response && $format_response ) {
		$response = array(
			'status'  => secupress_status( $response['status'] ),
			'class'   => sanitize_key( $response['status'] ),
			'message' => isset( $response['msgs'] ) ? secupress_format_message( $response['msgs'], $test_name ) : '',
			'fix_msg' => isset( $response['fix_msg'] ) ? secupress_format_message( $response['fix_msg'], $test_name ) : '',
		);
	}

	return $response;
}


// Fix callback.

add_action( 'admin_post_secupress_fixit', '__secupress_fixit_action_callback' );
add_action( 'wp_ajax_secupress_fixit',    '__secupress_fixit_action_callback' );
/**
 * Used to automatically fix a test in scanner page.
 *
 * @since 1.0
 * @return (string) json format or redirects the user
 **/
function __secupress_fixit_action_callback() {

	if ( empty( $_GET['test'] ) || empty( $_GET['_wpnonce'] ) ) {
		secupress_admin_die();
	}

	$test_name = esc_attr( $_GET['test'] );
	$nonce     = wp_verify_nonce( $_GET['_wpnonce'], 'secupress_fixit_' . $test_name );

	if ( ! $test_name || ! $nonce ) {
		secupress_admin_die();
	}

	$for_current_site = ! empty( $_GET['for-current-site'] );
	$response = secupress_fixit( $test_name, true, $for_current_site );

	secupress_admin_send_response_or_redirect( $response, 'scanners' );
}


/**
 * Get the result of a fix.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name.
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the fix for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 **/
function secupress_fixit( $test_name, $format_response = false, $for_current_site = false ) {
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$response = $classname::get_instance()->for_current_site( $for_current_site )->fix();
			/*
			 * $response is an array that MUST contain "status" and MUST contain "msgs".
			 */
		ob_end_flush();
	}

	if ( $response && $format_response ) {
		$response = array_merge( $response, array(
			'class'   => sanitize_key( $response['status'] ),
			'status'  => secupress_status( $response['status'] ),
			'message' => isset( $response['msgs'] ) ? secupress_format_message( $response['msgs'], $test_name ) : '',
		) );
		unset( $response['msgs'], $response['attempted_fixes'] );
	}

	return $response;
}


// Manual fix callback.

add_action( 'admin_post_secupress_manual_fixit', '__secupress_manual_fixit_action_callback' );
add_action( 'wp_ajax_secupress_manual_fixit',    '__secupress_manual_fixit_action_callback' );
/**
 * Used to manually fix a test in scanner page.
 *
 * @since 1.0
 * @return (string) json format or redirects the user.
 **/
function __secupress_manual_fixit_action_callback() {

	if ( empty( $_POST['test'] ) || empty( $_POST['secupress_manual_fixit-nonce'] ) ) {
		secupress_admin_die();
	}

	$test_name = esc_attr( $_POST['test'] );
	$nonce     = wp_verify_nonce( $_POST['secupress_manual_fixit-nonce'], 'secupress_manual_fixit-' . $test_name );

	if ( ! $test_name || ! $nonce ) {
		secupress_admin_die();
	}

	$for_current_site = ! empty( $_POST['for-current-site'] );
	$response = secupress_manual_fixit( $test_name, true, $for_current_site );

	secupress_admin_send_response_or_redirect( $response, 'scanners' );
}


/**
 * Get the result of a manual fix.
 *
 * @since 1.0
 *
 * @param (string) $test_name        The suffix of the class name.
 * @param (bool)   $format_response  Change the output format.
 * @param (bool)   $for_current_site If multisite, tell to perform the manual fix for the current site, not network-wide.
 *                                   It has no effect on non multisite installations.
 *
 * @return (array|bool) The scan result or false on failure.
 **/
function secupress_manual_fixit( $test_name, $format_response = false, $for_current_site = false ) {
	$response = false;

	if ( ! $test_name || ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
		return false;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', $test_name );

	$classname = 'SecuPress_Scan_' . $test_name;

	if ( class_exists( $classname ) ) {
		ob_start();
			@set_time_limit( 0 );
			$response = $classname::get_instance()->for_current_site( $for_current_site )->manual_fix();
			/*
			 * $response is an array that MUST contain "status" and MUST contain "msgs".
			 */
		ob_end_flush();
	}

	if ( $response && $format_response ) {
		$response = array_merge( $response, array(
			'class'   => sanitize_key( $response['status'] ),
			'status'  => secupress_status( $response['status'] ),
			'message' => isset( $response['msgs'] ) ? secupress_format_message( $response['msgs'], $test_name ) : '',
		) );
		unset( $response['msgs'], $response['attempted_fixes'] );
	}

	return $response;
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

// A simple shorthand to `die()`, depending on the admin context.

function secupress_admin_die() {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_error();
	}
	wp_nonce_ays( '' );
}


// A simple shorthand to send a json response, die, or redirect to one of our settings pages, depending on the admin context. It can also send poneys to mars.

function secupress_admin_send_response_or_redirect( $response, $redirect = false ) {
	if ( ! $response ) {
		secupress_admin_die();
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $response );
	}

	$redirect = $redirect ? secupress_admin_url( $redirect ) : wp_get_referer();

	wp_redirect( $redirect );
	die();
}



// Retrieve messages by their ID and format them by wrapping them in `<ul>` and `<li>` tags.

function secupress_format_message( $msgs, $test_name ) {
	$classname = 'SecuPress_Scan_' . $test_name;
	$messages  = $classname::get_instance()->get_messages();

	$output = '<ul>';

	foreach ( $msgs as $id => $atts ) {

		if ( ! isset( $messages[ $id ] ) ) {

			$string = __( 'Unknown message', 'secupress' );

		} elseif ( is_array( $messages[ $id ] ) ) {

			$count  = array_shift( $atts );
			$string = translate_nooped_plural( $messages[ $id ], $count );

		} else {

			$string = $messages[ $id ];

		}

		if ( $atts ) {
			foreach ( $atts as $i => $att ) {
				if ( is_array( $att ) ) {
					$atts[ $i ] = wp_sprintf_l( '%l', $att );
				}
			}
		}

		$output .= '<li>' . ( ! empty( $atts ) ? vsprintf( $string, $atts ) : $string ) . '</li>';
	}

	return $output . '</ul>';
}


/*------------------------------------------------------------------------------------------------*/
/* MEH ========================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Link to the configuration page of the plugin
 *
 * @since 1.0
 */
add_filter( 'plugin_action_links_' . plugin_basename( SECUPRESS_FILE ), '__secupress_settings_action_links' );

function __secupress_settings_action_links( $actions ) {
	if ( ! secupress_is_white_label() ) {
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http://secupress.me/support/', __( 'Support', 'secupress' ) ) );

		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http://docs.secupress.me', __( 'Docs', 'secupress' ) ) );
	}

	array_unshift( $actions, sprintf( '<a href="%s">%s</a>', secupress_admin_url( 'settings' ), __( 'Settings' ) ) );

	return $actions;
}


/**
 * Reset White Label values to SecuPress default values
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_resetwl', '__secupress_reset_white_label_values_ajax_post_cb' );

function __secupress_reset_white_label_values_ajax_post_cb() {
	if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_resetwl' ) ) {
		secupress_reset_white_label_values( true );
	}

	wp_safe_redirect( add_query_arg( 'page', 'secupress_settings', wp_get_referer() ) );
	die();
}


/**
 * Ban an IP address.
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress-ban-ip', '__secupress_ban_ip_ajax_post_cb' );

function __secupress_ban_ip_ajax_post_cb() {
	check_admin_referer( 'secupress-ban-ip' );

	if ( ! current_user_can( secupress_get_capability() ) || empty( $_REQUEST['ip'] ) ) {
		wp_nonce_ays( '' );
	}

	$ip = urldecode( $_REQUEST['ip'] );

	if ( ! filter_var( $_REQUEST['ip'], FILTER_VALIDATE_IP ) ) {
		wp_nonce_ays( '' );
	}

	if ( ! WP_DEBUG && secupress_get_ip() === $ip ) {
		wp_nonce_ays( '' );
	}

	$ban_ips = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips = is_array( $ban_ips ) ? $ban_ips : array();

	$ban_ips[ $ip ] = time() + YEAR_IN_SECONDS; // Now you got 1 year to think about your future, kiddo. In the meantime, go clean your room.

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ip_banned', $IP, $ban_ips );

	if ( apply_filters( 'write_ban_in_htaccess', true ) ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	$msg = sprintf( __( 'The IP address %s has been banned.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' );

	add_settings_error( 'general', 'ip_banned', $msg, 'updated' );
	set_transient( 'settings_errors', get_settings_errors(), 30 );

	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( $goback );
	die();
}


/**
 *
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_reset_settings', '__secupress_admin_post_reset_settings' );

function __secupress_admin_post_reset_settings() {
	if ( isset( $_GET['_wpnonce'], $_GET['module'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'secupress_reset_' . $_GET['module'] ) ) {
		do_action( 'wp_secupress_first_install', $_GET['module'] );
	}

	wp_safe_redirect( secupress_admin_url( 'modules', $_GET['module'] ) );
	die();
}


/**
 * White Label the plugin, if you need to
 *
 * @since 1.0
 *
 */
// add_filter( 'all_plugins', '__secupress_white_label' );
function __secupress_white_label( $plugins ) {
	if ( ! secupress_is_white_label() ) {
		return $plugins;
	}

	// We change the plugin's header
	$plugins[ SECUPRESS_PLUGIN_FILE ] = array(
		'Name'        => secupress_get_option( 'wl_plugin_name' ),
		'PluginURI'   => secupress_get_option( 'wl_plugin_URI' ),
		'Version'     => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['Version'] : '',
		'Description' => reset( ( secupress_get_option( 'wl_description', array() ) ) ),
		'Author'      => secupress_get_option( 'wl_author' ),
		'AuthorURI'   => secupress_get_option( 'wl_author_URI' ),
		'TextDomain'  => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['TextDomain'] : '',
		'DomainPath'  => isset( $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] ) ? $plugins[ SECUPRESS_PLUGIN_FILE ]['DomainPath'] : '',
	);

	return $plugins;
}


/**
 * When you're doing an update, the constant does not contain yet your option or any value, reset and redirect!
 *
 * @since 1.0
 */
// add_action( 'admin_init', '__secupress_check_no_empty_name', 11 ); ////

function __secupress_check_no_empty_name() {
	$wl_plugin_name = trim( secupress_get_option( 'wl_plugin_name' ) );

	if ( empty( $wl_plugin_name ) ) {
		secupress_reset_white_label_values( false );
		wp_safe_redirect( $_SERVER['REQUEST_URI'] );
		die();
	}
}



/**
 * Force our user agent header when we hit our urls //// X-Secupress header
 *
 * @since 1.0
 */
add_filter( 'http_request_args', '__secupress_add_own_ua', 10, 3 );

function __secupress_add_own_ua( $r, $url ) {
	if ( false !== strpos( $url, 'secupress.fr' ) ) {
		$r['user-agent'] = secupress_user_agent( $r['user-agent'] );
	}

	return $r;
}


add_filter( 'registration_errors', '__secupress_registration_test_errors', PHP_INT_MAX, 2 );

function __secupress_registration_test_errors( $errors, $sanitized_user_login ) {
	if ( ! $errors->get_error_code() && false !== strpos( $sanitized_user_login, 'secupress' ) ) {
		set_transient( 'secupress_registration_test', 'failed', HOUR_IN_SECONDS );
		$errors->add( 'secupress_registration_test', 'secupress_registration_test_failed' );
	}

	return $errors;
}


/**
 * Register all modules settings
 *
 * @return void
 * @since 1.0
 **/
add_action( 'admin_init', 'secupress_register_all_settings' );

function secupress_register_all_settings() {
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module_data ) {
			secupress_register_setting( $key );
		}
	}
}


/**
 * Set a transient to be read later to launch an async job
 *
 * @since 1.0
 * @return void
 **/
add_action( 'admin_post_secupress_toggle_file_scan', '__secupress_toggle_file_scan_ajax_post_cb' );

function __secupress_toggle_file_scan_ajax_post_cb() {

	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_toggle_file_scan' ) ) {
		wp_nonce_ays( '' );
	}
	if ( false === get_site_transient( 'secupress_toggle_file_scan' ) ) {
		set_site_transient( 'secupress_toggle_file_scan', time() );
	} else {
		delete_site_transient( 'secupress_toggle_file_scan' );
	}

	wp_redirect( wp_get_referer() );
	die();
}
