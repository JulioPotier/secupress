<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ADMIN POST / AJAX CALLBACKS ================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Scan callback.
 */
add_action( 'admin_post_secupress_scanner', 'secupress_scanit_ajax_post_cb' );
add_action( 'wp_ajax_secupress_scanner',    'secupress_scanit_ajax_post_cb' );
/**
 * Used to scan a test in scanner page.
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function secupress_scanit_ajax_post_cb() {
	if ( empty( $_GET['test'] ) ) {
		secupress_admin_die();
	}

	$test_name        = $_GET['test']; // WPCS: XSS ok.
	$for_current_site = ! empty( $_GET['for-current-site'] );
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : '';

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_scanner_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
	if ( isset( $_GET['delay'] ) ) {
		$delay  = max( min( 5, (int) $_GET['delay'] ), 0 );
		sleep( $delay );
	}
	$response   = secupress_scanit( $test_name, $doing_ajax, $for_current_site );
	secupress_admin_send_response_or_redirect( $response );
}


/**
 * Fix callback.
 */
add_action( 'admin_post_secupress_fixit', 'secupress_fixit_ajax_post_cb' );
add_action( 'wp_ajax_secupress_fixit',    'secupress_fixit_ajax_post_cb' );
/**
 * Used to automatically fix a test in scanner page.
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function secupress_fixit_ajax_post_cb() {
	if ( empty( $_GET['test'] ) ) {
		secupress_admin_die();
	}

	$test_name        = esc_attr( $_GET['test'] );
	$for_current_site = ! empty( $_GET['for-current-site'] );
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : '';

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


/**
 * Manual fix callback.
 */
add_action( 'admin_post_secupress_manual_fixit', 'secupress_manual_fixit_ajax_post_cb' );
add_action( 'wp_ajax_secupress_manual_fixit',    'secupress_manual_fixit_ajax_post_cb' );
/**
 * Used to manually fix a test in scanner page.
 * Prints a JSON or redirects the user.
 *
 * @since 1.0
 */
function secupress_manual_fixit_ajax_post_cb() {
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


/**
 * Get all translated strings for the scans UI.
 */
add_action( 'wp_ajax_secupress-get-scan-counters', 'secupress_get_scan_counters_ajax_cb' );
/**
 * Used to get all the needed translated strings and counters needed after each single scan/one-click scan.
 *
 * @since 1.0
 */
function secupress_get_scan_counters_ajax_cb() {
	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress-get-scan-counters' );

	$counts = secupress_get_scanner_counts();

	foreach ( array( 'notscannedyet', 'hasaction', 'good', 'warning', 'bad' ) as $status ) {
		$counts[ $status . '-text' ] = sprintf( _n( '%d issue', '%d issues', $counts[ $status ], 'secupress' ), $counts[ $status ] );
	}

	wp_send_json_success( $counts );
}


/**
 * Date of the last One-click scan.
 */
add_action( 'wp_ajax_secupress-update-oneclick-scan-date', 'secupress_update_oneclick_scan_date_ajax_cb' );
/**
 * Used to update the date of the last One-click scan.
 * Prints a JSON containing the HTML of the new line to insert in the page.
 *
 * @since 1.0
 */
function secupress_update_oneclick_scan_date_ajax_cb() {
	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress-update-oneclick-scan-date' );

	$items  = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );
	// Build the new item.
	$counts = secupress_get_scanner_counts();
	$item   = array(
		'percent' => round( $counts['good'] * 100 / $counts['total'] ),
		'grade'   => $counts['grade'],
		'time'    => time(),
	);

	// Get the previous percentage.
	if ( $items ) {
		$last_percent = end( $items );
		$last_percent = $last_percent['percent'];
	} else {
		$last_percent = -1;
	}

	// Add the new item and limit to 5 results.
	array_push( $items, $item );
	$items = array_slice( $items, -5, 5 );
	update_site_option( SECUPRESS_SCAN_TIMES, $items );

	// Send the formated new item.
	wp_send_json_success( secupress_formate_latest_scans_list_item( $item, $last_percent ) );
}

// WHITELIST IPs
add_action( 'admin_post_secupress-whitelist-ip', 'secupress_whitelist_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-whitelist-ip',    'secupress_whitelist_ip_ajax_post_cb' );
/**
 * Whitelist an IP address.
 *
 * @since 1.4.9
 */
function secupress_whitelist_ip_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-whitelist-ip' );
	secupress_check_user_capability();

	if ( empty( $_REQUEST['ip'] ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'IP address not provided.', 'secupress' ),
			'code'    => 'no_ip',
			'type'    => 'error',
		) );
	}

	// Test the IP.
	$ip          = trim( urldecode( $_REQUEST['ip'] ) );
	$original_ip = $ip;
	$is_list     = false;
	$sep         = "\n";
	if ( strpos( $ip, ', ' ) > 0 ) {
		$sep = ', ';
	} elseif ( strpos( $ip, ',' ) > 0 ) {
		$sep = ',';
	} elseif ( strpos( $ip, ';' ) > 0 ) {
		$sep = ';';
	} elseif ( strpos( $ip, ' ' ) > 0 ) {
		$sep = ' ';
	}
	if ( strpos( $ip, $sep ) > 0 ) {
		$is_list = true;
		$ip      = explode( $sep, $ip );
		$count_1 = count( $ip );
		$ip      = array_filter( $ip , function( $_ip ) {
			return secupress_ip_is_valid( $_ip, true );
		} );
		$count_2 = count( $ip );
	}

	if ( ! $is_list && ! secupress_ip_is_valid( $ip, true ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'This is not a valid IP address.', 'secupress' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		) );
	}

	if ( ! $is_list && ( secupress_ip_is_whitelisted( $ip ) ) ) {
		secupress_admin_send_message_die( [
			'message' => __( 'This IP address is already allowed.', 'secupress' ),
			'code'    => 'already_whitelisted',
			'type'    => 'error',
		] );
	}

	if ( $is_list && 0 === $count_2 ) {
		secupress_admin_send_message_die( [
			'message' => __( 'The list does not contains any valid IP address.', 'secupress' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		] );
	}

	// Add the IP to the option.
	$white_ips = get_site_option( SECUPRESS_WHITE_IP );
	$white_ips = is_array( $white_ips ) ? $white_ips : [];
	if ( ! is_array( $ip ) ) {
		$ip    = [ $ip ];
	}
	$ip        = array_flip( $ip );
	$white_ips = array_merge( $white_ips, $ip );

	update_site_option( SECUPRESS_WHITE_IP, $white_ips );

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ip_allowed', $ip, $white_ips );

	$referer_arg  = '&_wp_http_referer=' . urlencode( esc_url_raw( secupress_admin_url( 'modules', 'logs' ) ) );
	// Send a response.
	if ( ! $is_list ) {
		secupress_admin_send_message_die( [
			'message'    => sprintf( __( 'The IP address %s has been allowed.', 'secupress' ), '<code>' . esc_html( $original_ip ) . '</code>' ),
			'code'       => 'ip_whitelist',
			'tmplValues' => [
				[
					'ip'              => $original_ip,
					'unwhitelist_url' => esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unwhitelist-ip&ip=' . esc_attr( $original_ip ) . $referer_arg ), 'secupress-unwhitelist-ip_' . $original_ip ) ),
				],
			] ]
		);
	} else {
		$tmplValues = [];
		foreach ( $white_ips as $_ip => $time ) {
			$tmplValues[] = [   'ip'              => $_ip,
								'unwhitelist_url' => esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unwhitelist-ip&ip=' . esc_attr( $_ip ) . $referer_arg ), 'secupress-unwhitelist-ip_' . $_ip ) ),
							];
		}
		if ( $count_1 === $count_2 ) {
			secupress_admin_send_message_die( [
				'message'    => __( 'The IP address list has been allowed.', 'secupress' ),
				'code'       => 'ip_whitelist',
				'tmplValues' => $tmplValues,
			] );
		} else {
			secupress_admin_send_message_die( [
				'message'    => __( 'Some of the IP address list has been allowed.', 'secupress' ),
				'code'       => 'ip_whitelist',
				'tmplValues' => $tmplValues,
			] );
		}
	}
}


add_action( 'admin_post_secupress-unwhitelist-ip', 'secupress_unwhitelist_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-unwhitelist-ip',    'secupress_unwhitelist_ip_ajax_post_cb' );
/**
 * Unwhitelist an IP address.
 *
 * @since 1.4.9
 */
function secupress_unwhitelist_ip_ajax_post_cb() {
	// Make all security tests.
	if ( empty( $_REQUEST['ip'] ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'IP address not provided.', 'secupress' ),
			'code'    => 'no_ip',
			'type'    => 'error',
		) );
	}

	secupress_check_admin_referer( 'secupress-unwhitelist-ip_' . $_REQUEST['ip'] );
	secupress_check_user_capability();

	$ip = trim( urldecode( $_REQUEST['ip'] ) );

	// Remove the IP from the option.
	$white_ips = get_site_option( SECUPRESS_WHITE_IP );
	$white_ips = is_array( $white_ips ) ? $white_ips : [];
	if ( ! isset( $white_ips[ $ip ] ) ) {
		secupress_admin_send_message_die( [
			'message' => sprintf( __( 'The IP address %s is not allowed.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
			'code'    => 'ip_not_whitelisted',
		] );
	}

	unset( $white_ips[ $ip ] );

	if ( $white_ips ) {
		update_site_option( SECUPRESS_WHITE_IP, $white_ips );
	} else {
		delete_site_option( SECUPRESS_WHITE_IP );
	}

	/**
	 * Fires once a IP is unbanned.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip      The IP unbanned.
	 * @param (array)  $white_ips The list of IPs banned (keys) and the time they were banned (values).
	 */
	do_action( 'secupress.ip_unallowed', $ip, $white_ips );

	// Send a response.
	secupress_admin_send_message_die( array(
		'message' => sprintf( __( 'The IP address %s has been remove from the list.', 'secupress' ), '<code>' . esc_html( $ip ) . '</code>' ),
		'code'    => 'ip_unwhitelisted',
	) );
}


add_action( 'admin_post_secupress-clear-whitelist-ips', 'secupress_clear_whitelist_ips_ajax_post_cb' );
add_action( 'wp_ajax_secupress-clear-whitelist-ips',    'secupress_clear_whitelist_ips_ajax_post_cb' );
/**
 * Unwhitelist all IP addresses.
 *
 * @since 1.4.9
 */
function secupress_clear_whitelist_ips_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-clear-whitelist-ips' );
	secupress_check_user_capability();

	// Remove all IPs from the option.
	delete_site_option( SECUPRESS_WHITE_IP );

	/**
	 * Fires once all IPs are unbanned.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.ips_cleared' );

	// Send a response.
	secupress_admin_send_message_die( [
		'message' => __( 'All IP addresses have been removed from list.', 'secupress' ),
		'code'    => 'whitelisted_ips_cleared',
	] );
}

// BANNED IPs
add_action( 'admin_post_secupress-ban-ip', 'secupress_ban_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-ban-ip',    'secupress_ban_ip_ajax_post_cb' );
/**
 * Ban an IP address.
 *
 * @since 1.0
 */
function secupress_ban_ip_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-ban-ip' );
	secupress_check_user_capability();

	if ( empty( $_REQUEST['ip'] ) ) {
		secupress_admin_send_message_die( [
			'message' => __( 'IP address not provided.', 'secupress' ),
			'code'    => 'no_ip',
			'type'    => 'error',
		] );
	}

	// Test the IP.
	$ip          = trim( urldecode( $_REQUEST['ip'] ) );
	$original_ip = $ip;
	$is_list     = false;
	$sep         = "\n";
	$unbanned    = '';
	if ( strpos( $ip, ', ' ) > 0 ) {
		$sep = ', ';
	} elseif ( strpos( $ip, ',' ) > 0 ) {
		$sep = ',';
	} elseif ( strpos( $ip, ';' ) > 0 ) {
		$sep = ';';
	} elseif ( strpos( $ip, ' ' ) > 0 ) {
		$sep = ' ';
	}
	if ( strpos( $ip, $sep ) > 0 ) {
		$is_list = true;
		$ip      = explode( $sep, $ip );
		$count_1 = count( $ip );
		$ip      = array_filter( $ip , function( $_ip ) {
			return secupress_ip_is_valid( $_ip, true );
		} );
		$count_2 = count( $ip );
	}

	if ( ! $is_list && ! secupress_ip_is_valid( $ip, true ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'This is not a valid IP address.', 'secupress' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		) );
	}

	// Don't ban your IP
	if ( secupress_get_ip() === $ip ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'You cannot ban your own IP address.', 'secupress' ),
			'code'    => 'own_ip',
			'type'    => 'error',
		) );
	}

	// No valid IP in a list
	if ( $is_list && 0 === $count_2 ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'The list does not contains any valid IP address.', 'secupress' ),
			'code'    => 'invalid_ip',
			'type'    => 'error',
		) );
	}

	// Already banned
	$ban_ips = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips = is_array( $ban_ips ) ? $ban_ips : [];
	if ( ! $is_list && isset( $ban_ips[ $ip ] ) ) {
		secupress_admin_send_message_die( array(
			'message' => __( 'This IP is already banned.', 'secupress' ),
			'code'    => 'already_banned',
			'type'    => 'error',
		) );
	}
	// Transform the non list as a list now
	if ( ! is_array( $ip ) ) {
		$ip  = [ $ip ];
	}
	$ip      = array_flip( $ip );
	array_walk( $ip, function( &$_ip, $time ) {
		$_ip = strtotime('+10 years');
	});
	$ban_ips = array_merge( $ban_ips, $ip );

	// Update the ips now
	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

	$referer_arg  = '&_wp_http_referer=' . urlencode( esc_url_raw( secupress_admin_url( 'modules', 'logs' ) ) );
	$format       = __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' );
	$_time        = date_i18n( $format, strtotime('+10 years'));
	// Send a response.
	if ( ! $is_list ) {
		secupress_admin_send_message_die( [
			'message'    => sprintf( __( 'The IP address %s has been banned.', 'secupress' ) . $unbanned, '<code>' . esc_html( $original_ip ) . '</code>' ),
			'code'       => 'ip_banned',
			'tmplValues' => [
				[
					'ip'        => $original_ip,
					'time'      => $_time,
					'unban_url' => esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unban-ip&ip=' . esc_attr( $original_ip ) . $referer_arg ), 'secupress-unban-ip_' . $original_ip ) ),
				],
			] ]
		);
	} else {
		$tmplValues = [];
		foreach ( $ban_ips as $_ip => $time ) {
			$tmplValues[] = [   'ip'        => $_ip,
								'time'      => $_time,
								'unban_url' => esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unban-ip&ip=' . esc_attr( $_ip ) . $referer_arg ), 'secupress-unban-ip_' . $_ip ) ),
							];
		}
		if ( $count_1 === $count_2 ) {
			secupress_admin_send_message_die( [
				'message'    => __( 'The IP address list has been banned.' . $unbanned, 'secupress' ),
				'code'       => 'ip_banned',
				'tmplValues' => $tmplValues,
			] );
		} else {
			secupress_admin_send_message_die( [
				'message'    => __( 'Some of the IP address list has been banned.' . $unbanned, 'secupress' ),
				'code'       => 'ip_banned',
				'tmplValues' => $tmplValues,
			] );
		}
	}
}


add_action( 'admin_post_secupress-unban-ip', 'secupress_unban_ip_ajax_post_cb' );
add_action( 'wp_ajax_secupress-unban-ip',    'secupress_unban_ip_ajax_post_cb' );
/**
 * Unban an IP address.
 *
 * @since 1.0
 */
function secupress_unban_ip_ajax_post_cb() {
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

	$ip = urldecode( $_REQUEST['ip'] );

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


add_action( 'admin_post_secupress-clear-ips', 'secupress_clear_ips_ajax_post_cb' );
add_action( 'wp_ajax_secupress-clear-ips',    'secupress_clear_ips_ajax_post_cb' );
/**
 * Unban all IP addresses.
 *
 * @since 1.0
 */
function secupress_clear_ips_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'secupress-clear-ips' );
	secupress_check_user_capability();

	// Remove all IPs from the option.
	delete_site_option( SECUPRESS_BAN_IP );

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


add_action( 'admin_post_secupress_reset_settings', 'secupress_admin_post_reset_settings_post_cb' );
/**
 * Reset SecuPress settings or module settings.
 *
 * @since 1.4.4 Params $module & $bypass.
 * @since 1.0
 *
 * @author Julio Potier
 * @param (string) $module Empty by default, the module to be reset if $_GET is not defined.
 * @param (bool)   $bypass False by default, if true, the security will not be checked, already done by the caller.
 */
function secupress_admin_post_reset_settings_post_cb( $module = '', $bypass = false ) {
	if ( empty( $_GET['module'] ) && ! $module ) {
		secupress_admin_die();
	}

	$module = isset( $_GET['module'] ) ? $_GET['module'] : $module;
	if ( ! $bypass ) {
		// Make all security tests.
		secupress_check_admin_referer( 'secupress_reset_' . $module );
		secupress_check_user_capability();
	}

	secupress_delete_module_option( $module );
	/** This action is documented in inc/admin/upgrader.php */
	do_action( 'secupress.first_install', $module );

	if ( ! $bypass ) {
		secupress_add_transient_notice( __( 'Module settings reset.', 'secupress' ), 'updated', 'module-reset' );

		wp_safe_redirect( esc_url_raw( secupress_admin_url( 'modules', $module ) ) );
		die();
	}
}


add_action( 'wp_ajax_sanitize_move_login_slug', 'secupress_sanitize_move_login_slug_ajax_post_cb' );
/**
 * Sanitize a value for a Move Login slug.
 *
 * @since 1.2.5
 * @author Grégory Viguier
 */
function secupress_sanitize_move_login_slug_ajax_post_cb() {
	// Make all security tests.
	secupress_check_admin_referer( 'sanitize_move_login_slug' );
	secupress_check_user_capability();

	if ( empty( $_GET['default'] ) || ! isset( $_GET['slug'] ) ) {
		wp_send_json_error();
	}

	$default = sanitize_title( $_GET['default'] );

	if ( ! $default ) {
		wp_send_json_error();
	}

	if ( 'login' === $default ) {
		$slug = sanitize_title( $_GET['slug'], '', 'display' );
		// See secupress/inc/modules/users-login/settings/move-login.php.
		$slug = $slug ? $slug : '##-' . strtoupper( sanitize_title( __( 'Choose your login URL', 'secupress' ), '', 'display' ) ) . '-##';
	} else {
		$slug = sanitize_title( $_GET['slug'], $default, 'display' );
	}

	wp_send_json_success( $slug );
}


add_action( 'admin_post_nopriv_secupress_unlock_admin', 'secupress_unlock_admin_ajax_post_cb' );
/**
 * Send an unlock email if the provided address is from an admin
 *
 * @author Julio Potier
 * @since 1.3.2
 **/
function secupress_unlock_admin_ajax_post_cb() {
	if ( ! isset( $_POST['_wpnonce'], $_POST['email'] ) || ! is_email( $_POST['email'] ) || ! check_ajax_referer( 'secupress-unban-ip-admin', '_wpnonce' ) ) { // WPCS: CSRF ok.
		wp_die( 'Something went wrong.' );
	}
	$_CLEAN          = [];
	$_CLEAN['email'] = $_POST['email'];
	$user            = get_user_by( 'email', $_CLEAN['email'] );
	if ( ! secupress_is_user( $user ) || ! user_can( $user, 'manage_options' ) ) {
		wp_die( 'Something went wrong.' );
	}
	$url_remember = wp_login_url();
	$token        = strtolower( wp_generate_password( 10, false ) );
	set_transient( 'secupress_unlock_admin_key', $token, DAY_IN_SECONDS );
	$url_remove   = add_query_arg( '_wpnonce', $token, admin_url( 'admin-post.php?action=secupress_deactivate_module&module=move-login' ) );

	$subject      = __( '###SITENAME### – Unlock an administrator', 'secupress' );
	$message      = sprintf( __( 'Hello %1$s,
It seems you are locked out from the website ###SITENAME###.

You can now follow this link to your new login page (remember it!):
%2$s

Have a nice day !

Regards,
All at ###SITENAME###
###SITEURL###', 'secupress' ),
							$user->display_name,
							'<a href="' . $url_remember . '">' . $url_remember . '</a>'
					);
	if ( apply_filters( 'secupress.plugins.move_login.email.deactivation_link', true ) ) {
		$message .= "\n" . sprintf( __( "ps: you can also deactivate the Move Login module:\n%s", 'secupress' ), '<a href="' . $url_remove . '">' . $url_remove . '</a> ' . __( '(Valid 1 day)', 'secupress' ) );
	}

	/**
	 * Filter the mail subject
	 * @param (string) $subject
	 * @param (WP_User) $user
	 * @since 2.2
	 */
	$subject = apply_filters( 'secupress.mail.unlock_administrator.subject', $subject, $user );
	/**
	 * Filter the mail message
	 * @param (string) $message
	 * @param (WP_User) $user
	 * @param (string) $url_remove
	 * @param (string) $url_remember
	 * @since 2.2
	 */
	$message = apply_filters( 'secupress.mail.unlock_administrator.message', $message, $user, $url_remove, $url_remember );


	$sent = secupress_send_mail( $_CLEAN['email'], $subject, $message );
	secupress_die( $sent ? __( 'Email sent, check your mailbox.', 'secupress' ) : __( 'Email not sent, please contact the support.', 'secupress' ), __( 'Email', 'secupress' ), array( 'force_die' => true ) );
}

add_action( 'admin_post_nopriv_secupress_deactivate_module', 'secupress_deactivate_module_admin_post_cb' );
/**
 * Can deactivate a module from a link sent by secupress_unlock_admin_ajax_post_cb()
 *
 * @author Julio Potier
 * @since 1.3.2
 **/
function secupress_deactivate_module_admin_post_cb() {
	if ( ! isset( $_GET['_wpnonce'], $_GET['module'] ) || empty( $_GET['_wpnonce'] ) || ! get_transient( 'secupress_unlock_admin_key' ) || ! hash_equals( get_transient( 'secupress_unlock_admin_key' ), $_GET['_wpnonce'] ) ) {
		wp_die( 'Something went wrong.' );
	}
	delete_transient( 'secupress_unlock_admin_key' );
	secupress_deactivate_submodule( 'users-login', array( 'move-login' ) );
	wp_redirect( wp_login_url( secupress_admin_url( 'modules', 'users-login' ) ) );
	die();
}

add_action( 'admin_post_secupress_reset_all_settings', 'secupress_reset_all_settings_admin_post_cb' );
/**
 * Will reset the settings like a fresh install
 *
 * @since 1.4.4
 * @author Julio Potier
 **/
function secupress_reset_all_settings_admin_post_cb() {
	if ( ! isset( $_GET['_wpnonce'] ) ) {
		wp_die( 'Something went wrong.' );
	}

	secupress_check_admin_referer( 'secupress_reset_all_settings' );
	secupress_check_user_capability();

	$modules = secupress_get_modules();
	foreach ( $modules as $key => $module ) {

		if ( isset( $module['with_reset_box'] ) && false === $module['with_reset_box'] ) {
			continue;
		}
		secupress_admin_post_reset_settings_post_cb( $key, true );
	}

	secupress_add_transient_notice( __( 'All modules settings reset', 'secupress' ), 'updated', 'module-reset' );

	wp_safe_redirect( wp_get_referer() );
	die();
}

add_action( 'wp_ajax_secupress_set_scan_speed', 'secupress_set_scan_speed_admin_post_cb' );
/**
 * Set scanner speed
 *
 * @since 1.4.4
 * @author Julio Potier
 **/
function secupress_set_scan_speed_admin_post_cb() {
	$old_value       = secupress_get_option( 'scan-speed', 0 );
	$allowed_values  = [ 'max' => 0, 'normal' => 250, 'low' => 1000 ];
	$_clean          = [];
	$_clean['text']  = isset( $allowed_values[ $_GET['value'] ] ) ? $_GET['value'] : 'max';
	$_clean['value'] = isset( $allowed_values[ $_GET['value'] ] ) ? $allowed_values[ $_GET['value'] ] : 0;

	if ( ! isset( $_GET['_wpnonce'], $_GET['value'] ) || ! check_ajax_referer( 'secupress-set-scan-speed', '_wpnonce', false ) ) {
		$allowed_values = array_flip( $allowed_values );
		wp_send_json_error( [ 'val' => $old_value, 'text' => $allowed_values[ $old_value ] ] );
	}

	/**
	* Filter the milliseconds between scans.
	*
	* @param (int) $value Defaults values are 0, 250 (1/4 sec), 1000 (1 sec)
	* @since 1.4.5
	* @author Julio Potier
	*/
	$value = apply_filters( 'secupress.scanner.scan-speed', $_clean['value'] );
	secupress_set_option( 'scan-speed', $value );
	wp_send_json_success( [ 'val' => $_clean['value'], 'text' => $_clean['text'] ] );
}


add_action( 'wp_ajax_secupress_send_deactivation_info', 'secupress_send_deactivation_info_admin_post_cb' );
/**
 * Send the deactivation reason on secupress.me
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) json
 **/
function secupress_send_deactivation_info_admin_post_cb() {
	if ( ! isset( $_GET['nonce'], $_GET['reason'] ) || ! wp_verify_nonce( $_GET['nonce'], 'deactivation-info' ) ) {
		wp_send_json_error();
	}
	set_site_transient( 'secupress-deactivation-form', 1, HOUR_IN_SECONDS );
	$args = [
		'timeout'    => 0.01,
		'blocking'   => false,
		'body'       => esc_html( $_GET['reason'] )
	];
	wp_remote_post( SECUPRESS_WEB_MAIN . 'api/reason.php', $args );
	wp_send_json_success();
}

add_action( 'wp_ajax_secupress_malwareScanStatus', 'secupress_get_malwarescastatus_admin_post_cb' );
/**
 * Return the current scanned folders
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string)
 **/
function secupress_get_malwarescastatus_admin_post_cb() {
	$response                      = [];
	if ( ! isset( $_GET['_wpnonce'] ) || ! check_ajax_referer( 'secupress_malwareScanStatus', '_wpnonce', false ) ) {
		$response['malwareScanStatus'] = false;
		wp_send_json_error( $response );
	}
	$response                      = [];
	$response['malwareScanStatus'] = ! secupress_file_monitoring_get_instance()->is_monitoring_running();
	$response['currentItems']      = get_site_transient( SECUPRESS_FULL_FILETREE ) !== false ? array_map( function( $val ) { return str_replace( ABSPATH, '/', $val ); }, get_site_transient( SECUPRESS_FULL_FILETREE ) ) : [];
	wp_send_json_success( $response );
}

add_action( 'admin_post_secupress-regen-keys', 'secupress_regen_hash_key_admin_post_cb' );
/**
 * Set a new has_key, this will reset the salt keys too
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_regen_hash_key_admin_post_cb() {
	global $current_user;
	if ( ! isset( $_GET['_wpnonce'] ) || ! check_ajax_referer( 'secupress-regen-keys', '_wpnonce', false ) ) {
		wp_die( 'Something went wrong.' );
	}
	// Do not use secupress_get_option() here.
	$options             = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$options['hash_key'] = secupress_generate_key( 64 );
	secupress_update_options( $options );

	secupress_auto_login( 'Salt_Keys' );
}

add_action( 'admin_post_secupress_accept_notification', 'secupress_accept_notification_admin_post_cb' );
/**
 * Validate the Slack Notification
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_accept_notification_admin_post_cb() {
	if ( ! isset( $_GET['_wpnonce'], $_GET['type'] ) || ! check_ajax_referer( 'secupress_accept_notification-type-' . $_GET['type'] ) ) {
		wp_die( 'Something went wrong.' );
	}
	secupress_set_option( 'notification-types_' . $_GET['type'], secupress_get_module_option( 'notification-types_slack', false, 'alerts' ) ); // WPCS: XSS Ok.
	wp_redirect( secupress_admin_url( 'modules', 'alerts#row-notification-types_slack' ) );
	die();
}


add_action( 'wp_ajax_dismiss-sp-pointer', 'secupress_dismiss_pointer_admin_post_cb' );
/**
 * Dismiss our pointers
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) JSON
 **/
function secupress_dismiss_pointer_admin_post_cb( $_pointer = '' ) {
	$pointer = isset( $_POST['pointer'] ) ? sanitize_key( $_POST['pointer'] ) : $_pointer;

	if ( ! $_pointer && ( ! $pointer || ! check_ajax_referer( 'dismiss-pointer_' . $pointer, '_ajaxnonce', false ) ) ) {
		wp_send_json_error();
	}

	$dismissed = array_filter( explode( ',', (string) get_user_meta( get_current_user_id(), 'dismissed_wp_pointers', true ) ) );

	if ( ! $_pointer && in_array( $pointer, $dismissed, true ) ) {
		wp_send_json_error();
	}

	$dismissed[] = $pointer;
	$dismissed   = implode( ',', $dismissed );

	update_user_meta( get_current_user_id(), 'dismissed_wp_pointers', $dismissed );
	if ( ! $_pointer ) {
		wp_send_json_success();
	}
}

// add_action( 'admin_post_http_log_actions', 'secupress_http_log_actions_admin_post_cb' );
function secupress_http_log_actions_admin_post_cb() {
	if ( ! isset( $_POST['_wpnonce'], $_POST['log_id'], $_POST['http_log'] ) || ! check_admin_referer( 'http_log_actions' . $_POST['log_id'] ) ) {
		die( '0' );
	}
	$http_logs = get_option( SECUPRESS_HTTP_LOGS );
	$http_logs = is_array( $http_logs ) ? $http_logs : [];
	$options   = isset( $_POST['http_log']['options'] ) ? $_POST['http_log']['options'] : [];
	unset( $_POST['http_log']['options'] );
	$_CLEAN    = $_POST['http_log'];
	foreach ( $_CLEAN as $url => $values ) {
		if ( empty( $values['index'] ) || '1' === $values['index'] ) {
			unset( $_CLEAN[ $url ] );
			continue;
		}

		$parsed_url         = shortcode_atts( [ 'scheme' => '', 'host' => '', 'path' => '', 'query' => '' ], wp_parse_url( $url ) );
		if ( empty( $parsed_url['scheme'] ) ) {
			unset( $_CLEAN[ $url ] );
			continue;
		}
		if ( ! empty( $parsed_url['query'] ) ) {
			parse_str( html_entity_decode( $parsed_url['query'] ), $get_params );
			if ( ! empty( $options['ignore-param'] ) ) {
				$get_params = array_diff_key( $get_params, array_flip( $options['ignore-param'] ) );
			}
			ksort( $get_params );
			$path_name      = $parsed_url['scheme'] . '://' . untrailingslashit( $parsed_url['host'] ) . $parsed_url['path'];
			$query          = http_build_query( $get_params );
			$query          = ! empty( $query ) ? '?' . $query : '';
			$temp           = $_CLEAN[ $url ];
			unset( $_CLEAN[ $url ] );
			$url            = $path_name . $query;
			$_CLEAN[ $url ] = $temp;
		}
		if ( isset( $options ) ) {
			$_CLEAN[ $url ]['options'] = $options;
			unset( $options );
		}

		if ( ! isset( $http_logs[ $url ]['since'] ) ) {
			$_CLEAN[ $url ]['since'] = time();
		}
		if ( ! isset( $http_logs[ $url ]['hits'] ) ) {
			$_CLEAN[ $url ]['hits']  = 0;
		}
		// Always reset the last call on save/update.
		$_CLEAN[ $url ]['last']      = 0;
	}
	$http_logs = array_merge( $http_logs, $_CLEAN );
	ksort( $http_logs );
	update_option( SECUPRESS_HTTP_LOGS, $http_logs, false );
	wp_safe_redirect( wp_get_referer() );
	die();
}
