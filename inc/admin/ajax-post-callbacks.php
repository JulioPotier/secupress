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
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function __secupress_scanit_action_callback() {
	if ( empty( $_GET['test'] ) ) { // WPCS: CSRF ok.
		secupress_admin_die();
	}

	$test_name        = esc_attr( $_GET['test'] ); // WPCS: CSRF ok.
	$for_current_site = ! empty( $_GET['for-current-site'] ); // WPCS: CSRF ok.
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : ''; // WPCS: CSRF ok.

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_scanner_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
	$response   = secupress_scanit( $test_name, $doing_ajax, $for_current_site );

	secupress_admin_send_response_or_redirect( $response );
}


// Fix callback.

add_action( 'admin_post_secupress_fixit', '__secupress_fixit_action_callback' );
add_action( 'wp_ajax_secupress_fixit',    '__secupress_fixit_action_callback' );
/**
 * Used to automatically fix a test in scanner page.
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function __secupress_fixit_action_callback() {
	if ( empty( $_GET['test'] ) ) { // WPCS: CSRF ok.
		secupress_admin_die();
	}

	$test_name        = esc_attr( $_GET['test'] ); // WPCS: CSRF ok.
	$for_current_site = ! empty( $_GET['for-current-site'] ); // WPCS: CSRF ok.
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : ''; // WPCS: CSRF ok.

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_fixit_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
	$response   = secupress_fixit( $test_name, $doing_ajax, $for_current_site );

	// If not ajax, perform a scan.
	if ( ! $doing_ajax ) {
		secupress_scanit( $test_name, false, $for_current_site );
	}

	secupress_admin_send_response_or_redirect( $response );
}


// Manual fix callback.

add_action( 'admin_post_secupress_manual_fixit', '__secupress_manual_fixit_action_callback' );
add_action( 'wp_ajax_secupress_manual_fixit',    '__secupress_manual_fixit_action_callback' );
/**
 * Used to manually fix a test in scanner page.
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function __secupress_manual_fixit_action_callback() {
	if ( empty( $_POST['test'] ) ) { // WPCS: CSRF ok.
		secupress_admin_die();
	}

	$test_name        = esc_attr( $_POST['test'] ); // WPCS: CSRF ok.
	$for_current_site = ! empty( $_POST['for-current-site'] ); // WPCS: CSRF ok.
	$site_id          = $for_current_site && ! empty( $_POST['site'] ) ? '-' . absint( $_POST['site'] ) : ''; // WPCS: CSRF ok.

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_manual_fixit_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
	$response   = secupress_manual_fixit( $test_name, $doing_ajax, $for_current_site );

	// If not ajax, perform a scan.
	if ( ! $doing_ajax ) {
		secupress_scanit( $test_name, false, $for_current_site );
	}

	secupress_admin_send_response_or_redirect( $response );
}


// Date of the last One-click scan.

add_action( 'wp_ajax_secupress-update-oneclick-scan-date', '__secupress_update_oneclick_scan_date' );
/**
 * Used to update the date of the last One-click scan.
 * Prints a JSON containing the HTML of the new line to insert in the page.
 *
 * @since 1.0
 */
function __secupress_update_oneclick_scan_date() {
	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress-update-oneclick-scan-date' );

	$last_pc = -1;
	$counts  = secupress_get_scanner_counts();
	$time    = array(
		'percent' => $counts['good'] * 100 / $counts['total'],
		'grade'   => $counts['grade'],
		'time'    => time(),
	);

	$times = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );

	if ( $times ) {
		$last_pc = end( $times );
		$last_pc = $last_pc['percent'];
	}

	array_push( $times, $time );
	// Limit to 5 results.
	$times = array_slice( $times, -5, 5 );

	update_site_option( SECUPRESS_SCAN_TIMES, $times );

	$icon = 'right';

	if ( $last_pc > -1 ) {
		if ( $last_pc < $time['percent'] ) {
			$icon = 'up';
		} elseif ( $last_pc > $time['percent'] ) {
			$icon = 'down';
		}
	}

	$out = sprintf(
		'<li class="hidden" data-percent="%1$d"><span class="dashicons mini dashicons-arrow-%2$s-alt2" aria-hidden="true"></span><strong>%3$s (%1$d %%)</strong> <span class="timeago">%4$s</span></li>',
		round( $time['percent'] ),
		$icon,
		$time['grade'],
		sprintf( __( '%s ago' ), human_time_diff( $time['time'] ) )
	);

	wp_send_json_success( $out );
}


add_action( 'admin_post_secupress-ban-ip', '__secupress_ban_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-ban-ip',    '__secupress_ban_ip_ajax_post_cb' );
/**
 * Ban an IP address.
 *
 * @since 1.0
 */
function __secupress_ban_ip_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-ban-ip' );
	secupress_check_user_capability();

	if ( empty( $_REQUEST['ip'] ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'IP address not provided.', 'secupress' ),
			'code'    => 'no_ip',
			'type'    => 'error',
		) );
	}

	// Test the IP.
	$ip = urldecode( $_REQUEST['ip'] );

	if ( ! secupress_ip_is_valid( $ip ) ) {
		secupress_admin_send_message_die( array(
			'message' => sprintf( __( '%s is not a valid IP address.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		) );
	}

	if ( secupress_ip_is_whitelisted( $ip ) || secupress_get_ip() === $ip ) {
		secupress_admin_send_message_die( array(
			'message' => sprintf( __( 'The IP address %s is whitelisted.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
			'code'    => 'own_ip',
			'type'    => 'error',
		) );
	}

	// Add the IP to the option.
	$ban_ips = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips = is_array( $ban_ips ) ? $ban_ips : array();

	$ban_ips[ $ip ] = time() + YEAR_IN_SECONDS * 100; // Now you got 100 years to think about your future, kiddo. In the meantime, go clean your room.

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	// Add the IP to the `.htaccess` file.
	if ( secupress_write_in_htaccess_on_ban() ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

	$referer_arg = '&_wp_http_referer=' . urlencode( esc_url_raw( secupress_admin_url( 'modules', 'logs' ) ) );

	// Send a response.
	secupress_admin_send_message_die( array(
		'message'    => sprintf( __( 'The IP address %s has been banned.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
		'code'       => 'ip_banned',
		'tmplValues' => array(
			array(
				'ip'        => $ip,
				'time'      => __( 'Forever', 'secupress' ),
				'unban_url' => esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unban-ip&ip=' . esc_attr( $ip ) . $referer_arg ), 'secupress-unban-ip_' . $ip ) ),
			),
		),
	) );
}


add_action( 'admin_post_secupress-unban-ip', '__secupress_unban_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-unban-ip',    '__secupress_unban_ip_ajax_post_cb' );
/**
 * Unban an IP address.
 *
 * @since 1.0
 */
function __secupress_unban_ip_ajax_post_cb() {
	// Make all security tests.
	if ( empty( $_REQUEST['ip'] ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'IP address not provided.', 'secupress' ),
			'code'    => 'no_ip',
			'type'    => 'error',
		) );
	}

	secupress_check_admin_referer( 'secupress-unban-ip_' . $_REQUEST['ip'] );
	secupress_check_user_capability();

	// Test the IP.
	$ip = urldecode( $_REQUEST['ip'] );

	if ( ! secupress_ip_is_valid( $ip ) ) {
		secupress_admin_send_message_die( array(
			'message' => sprintf( __( '%s is not a valid IP address.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		) );
	}

	// Remove the IP from the option.
	$ban_ips = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips = is_array( $ban_ips ) ? $ban_ips : array();

	if ( empty( $ban_ips[ $ip ] ) ) {
		secupress_admin_send_message_die( array(
			'message' => sprintf( __( 'The IP address %s is not banned.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
			'code'    => 'ip_not_banned',
		) );
	}

	unset( $ban_ips[ $ip ] );

	if ( $ban_ips ) {
		update_site_option( SECUPRESS_BAN_IP, $ban_ips );
	} else {
		delete_site_option( SECUPRESS_BAN_IP );
	}

	// Remove the IP from the `.htaccess` file.
	if ( secupress_write_in_htaccess_on_ban() ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	/**
	 * Fires once a IP is unbanned.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip      The IP unbanned.
	 * @param (array)  $ban_ips The list of IPs banned (keys) and the time they were banned (values).
	 */
	do_action( 'secupress.ban.ip_unbanned', $ip, $ban_ips );

	// Send a response.
	secupress_admin_send_message_die( array(
		'message' => sprintf( __( 'The IP address %s has been unbanned.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
		'code'    => 'ip_unbanned',
	) );
}


add_action( 'admin_post_secupress-clear-ips', '__secupress_clear_ips_ajax_post_cb' );
add_action( 'wp_ajax_secupress-clear-ips',    '__secupress_clear_ips_ajax_post_cb' );
/**
 * Unban all IP addresses.
 *
 * @since 1.0
 */
function __secupress_clear_ips_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-clear-ips' );
	secupress_check_user_capability();

	// Remove all IPs from the option.
	delete_site_option( SECUPRESS_BAN_IP );

	// Remove all IPs from the `.htaccess` file.
	if ( secupress_write_in_htaccess_on_ban() ) {
		secupress_write_htaccess( 'ban_ip' );
	}

	/**
	 * Fires once all IPs are unbanned.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.ban.ips_cleared' );

	// Send a response.
	secupress_admin_send_message_die( array(
		'message' => __( 'All IP addresses have been unbanned.', 'secupress' ),
		'code'    => 'banned_ips_cleared',
	) );
}


add_action( 'admin_post_secupress_reset_settings', '__secupress_admin_post_reset_settings' );
/**
 * Reset SecuPress settings or module settings.
 *
 * @since 1.0
 */
function __secupress_admin_post_reset_settings() {
	if ( empty( $_GET['module'] ) ) {
		secupress_admin_die();
	}
	// Make all security tests.
	secupress_check_admin_referer( 'secupress_reset_' . $_GET['module'] );
	secupress_check_user_capability();

	/** This action is documented in inc/admin/upgrader.php */
	do_action( 'secupress.first_install', $_GET['module'] );

	wp_safe_redirect( esc_url_raw( secupress_admin_url( 'modules', $_GET['module'] ) ) );
	die();
}


add_filter( 'http_request_args', '__secupress_add_own_ua', 10, 3 );
/**
 * Force our user agent header when we hit our urls
 *
 * @since 1.0
 *
 * @param (array)  $r   The request parameters.
 * @param (string) $url The request URL.
 *
 * @return (array)
 */
function __secupress_add_own_ua( $r, $url ) {
	if ( false !== strpos( $url, 'secupress.me' ) ) {
		$r['headers']['x-secupress'] = secupress_user_agent( $r['user-agent'] );
	}

	return $r;
}


add_filter( 'registration_errors', '__secupress_registration_test_errors', PHP_INT_MAX, 2 );
/**
 * This is used in the Subscription scan to test user registrations from the login page.
 *
 * @since 1.0
 * @see `register_new_user()`
 *
 * @param (object) $errors               A WP_Error object containing any errors encountered during registration.
 * @param (string) $sanitized_user_login User's username after it has been sanitized.
 *
 * @return (object) The WP_Error object with a new error if the user name is blacklisted.
 */
function __secupress_registration_test_errors( $errors, $sanitized_user_login ) {
	if ( ! $errors->get_error_code() && false !== strpos( $sanitized_user_login, 'secupress' ) ) {
		set_transient( 'secupress_registration_test', 'failed', HOUR_IN_SECONDS );
		$errors->add( 'secupress_registration_test', 'secupress_registration_test_failed' );
	}

	return $errors;
}


add_action( 'admin_init', 'secupress_register_all_settings' );
/**
 * Register all modules settings.
 *
 * @since 1.0
 */
function secupress_register_all_settings() {
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module_data ) {
			secupress_register_setting( $key );
		}
	}
}


add_action( 'admin_post_secupress_toggle_file_scan', '__secupress_toggle_file_scan_ajax_post_cb' );
/**
 * Set a transient to be read later to launch an async job.
 *
 * @since 1.0
 */
function __secupress_toggle_file_scan_ajax_post_cb() {
	if ( empty( $_GET['turn'] ) ) {
		secupress_admin_die();
	}

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_toggle_file_scan' );

	if ( 'on' === $_GET['turn'] ) {
		secupress_set_site_transient( 'secupress_toggle_file_scan', time() );
		set_site_transient( 'secupress_toggle_queue', true, 30 );
	} else {
		secupress_delete_site_transient( 'secupress_toggle_file_scan' );
		delete_site_transient( 'secupress_toggle_queue' );
	}

	wp_redirect( esc_url_raw( wp_get_referer() ) );
	die();
}
