<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ADMIN POST / AJAX CALLBACKS ================================================================== */
/*------------------------------------------------------------------------------------------------*/

// Scan callback.

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

	$test_name        = esc_attr( $_GET['test'] );
	$for_current_site = ! empty( $_GET['for-current-site'] );
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : '';

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_scanner_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
	$response   = secupress_scanit( $test_name, $doing_ajax, $for_current_site );

	secupress_admin_send_response_or_redirect( $response );
}


// Fix callback.

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


// Manual fix callback.

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


// Get all translated strings for the scans UI.

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


// Date of the last One-click scan.

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


add_action( 'admin_post_secupress_reset_settings', 'secupress_admin_post_reset_settings_post_cb' );
/**
 * Reset SecuPress settings or module settings.
 *
 * @since 1.0
 */
function secupress_admin_post_reset_settings_post_cb() {
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


add_action( 'wp_ajax_secupress_recovery_email', 'secupress_recovery_email_ajax_post_cb' );
/**
 * Set the recovery email via notice, if possible
 *
 * @author Julio Potier
 * @since 1.0
 */
function secupress_recovery_email_ajax_post_cb() {
	secupress_callback_update_user_contactmethods( get_current_user_id() );
	$user  = wp_get_current_user();
	$dummy = new stdClass();

	secupress_user_profile_update_errors( $dummy, false, $user );
}


add_action( 'admin_post_secupress_refresh_bad_plugins', 'secupress_refresh_bad_plugins_list_ajax_post_cb' );
/**
 * Call the refresh of the vulnerable plugins.
 * Moved from Pro to Free + renamed. Originally `secupress_refresh_bad_plugins_ajax_post_cb()` and `secupress_refresh_vulnerable_plugins()`.
 *
 * @since 1.1.3
 */
function secupress_refresh_bad_plugins_list_ajax_post_cb() {
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'detect-bad-plugins' ) ) {
		secupress_admin_die();
	}

	$plugins  = get_plugins();
	$plugins  = wp_list_pluck( $plugins, 'Version' );
	$args     = array( 'body' => array( 'items' => $plugins, 'type' => 'plugin' ) );

	$response = wp_remote_post( SECUPRESS_WEB_MAIN . 'api/plugin/vulns.php', $args );

	if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
		$response = wp_remote_retrieve_body( $response );

		// Store the result only if it's not an error (not -1, -2, -3, or -99).
		if ( (int) $response > 0 ) {
			update_site_option( 'secupress_bad_plugins', $response );
		}
	}
}


add_action( 'admin_post_secupress_refresh_bad_themes', 'secupress_refresh_bad_themes_list_ajax_post_cb' );
/**
 * Call the refresh of the vulnerable themes.
 * Moved from Pro to Free + renamed. Originally `secupress_refresh_bad_themes_ajax_post_cb()` and `secupress_refresh_vulnerable_themes()`.
 *
 * @return void
 * @since 1.0
 */
function secupress_refresh_bad_themes_list_ajax_post_cb() {
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'detect-bad-themes' ) ) {
		secupress_admin_die();
	}

	$themes = wp_get_themes();
	$themes = wp_list_pluck( $themes, 'Version' );
	$args   = array( 'body' => array( 'items' => $themes, 'type' => 'theme' ) );

	$response = wp_remote_post( SECUPRESS_WEB_MAIN . 'api/plugin/vulns.php', $args );

	if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
		$response = wp_remote_retrieve_body( $response );

		// Store the result only if it's not an error (not -1, -2, -3, or -99).
		if ( (int) $response > 0 ) {
			update_site_option( 'secupress_bad_themes', $response );
		}
	}
}


/*------------------------------------------------------------------------------------------------*/
/* ADMIN POST / AJAX CALLBACKS FOR THE MAIN SETTINGS ============================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_post_secupress_update_global_settings_api-key', 'secupress_global_settings_api_key_ajax_post_cb' );
/**
 * Deal with the license.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 */
function secupress_global_settings_api_key_ajax_post_cb() {
	// Make all security tests.
	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_update_global_settings_api-key' );

	// Previous values.
	$old_values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$old_values = is_array( $old_values ) ? $old_values : array();
	$old_email  = ! empty( $old_values['consumer_email'] ) ? sanitize_email( $old_values['consumer_email'] )    : '';
	$old_key    = ! empty( $old_values['consumer_key'] )   ? sanitize_text_field( $old_values['consumer_key'] ) : '';
	$old_is_pro = ! empty( $old_values['site_is_pro'] )    ? 1 : 0;
	$has_old    = $old_email && $old_key;
	$old_email  = $has_old ? $old_email  : '';
	$old_key    = $has_old ? $old_key    : '';
	$old_is_pro = $has_old ? $old_is_pro : 0;
	unset( $old_values['sanitized'] ); // Back compat'.
	// New values.
	$values     = ! empty( $_POST['secupress_settings'] ) && is_array( $_POST['secupress_settings'] ) ? $_POST['secupress_settings'] : array();
	$values     = secupress_array_merge_intersect( $values, array(
		'consumer_email' => '',
		'consumer_key'   => '',
	) );
	$values['install_time'] = ! empty( $old_values['install_time'] ) ? (int) $old_values['install_time'] : time();
	$new_email  = $values['consumer_email'] ? sanitize_email( $values['consumer_email'] )    : '';
	$new_key    = $values['consumer_key']   ? sanitize_text_field( $values['consumer_key'] ) : '';
	$has_new    = $new_email && $new_key;
	$new_email  = $has_new ? $new_email : '';
	$new_key    = $has_new ? $new_key   : '';
	// Action.
	$action     = $has_old && $old_is_pro ? 'deactivate' : 'activate';

	if ( ! secupress_has_pro() ) {
		// The Pro version is not activated.
		$action = false;

		if ( $has_old ) {
			// Send the previous values back.
			$values['consumer_email'] = $old_email;
			$values['consumer_key']   = $old_key;

			if ( $old_is_pro ) {
				$values['site_is_pro'] = 1;
			}
		} else {
			// Empty the new values.
			unset( $values['consumer_email'], $values['consumer_key'] );
		}

		add_settings_error( 'general', 'response_error', __( 'You must install and activate the Pro version first.', 'secupress' ) );
	}
	elseif ( 'deactivate' === $action ) {
		// To deactivate, use old values.
		$values['consumer_email'] = $old_email;
		$values['consumer_key']   = $old_key;
	}
	elseif ( $has_new ) {
		// To activate, use new values.
		$values['consumer_email'] = $new_email;
		$values['consumer_key']   = $new_key;
	}
	else {
		// PEBCAK, new values are not good.
		$action = false;

		if ( ! $values['consumer_email'] && ! $values['consumer_key'] ) {
			add_settings_error( 'general', 'response_error', __( 'Please provide a valid email address and your license key.', 'secupress' ) );
		} elseif ( ! $values['consumer_email'] ) {
			add_settings_error( 'general', 'response_error', __( 'Please provide a valid email address.', 'secupress' ) );
		} else {
			add_settings_error( 'general', 'response_error', __( 'Please provide your license key.', 'secupress' ) );
		}

		if ( $has_old ) {
			// Send the previous values back.
			$values['consumer_email'] = $old_email;
			$values['consumer_key']   = $old_key;

			if ( $old_is_pro ) {
				$values['site_is_pro'] = 1;
			}
		} else {
			// Empty the new values.
			unset( $values['consumer_email'], $values['consumer_key'] );
		}
	}

	if ( 'deactivate' === $action ) {
		$values = secupress_global_settings_deactivate_pro_license( $values );
	} else {
		$values = secupress_global_settings_activate_pro_license( $values, $old_values );

		if ( empty( $values['site_is_pro'] ) && ! get_settings_errors( 'general' ) ) {
			add_settings_error( 'general', 'response_error', __( 'Your license key seems invalid.', 'secupress' ) );
		}
	}

	// Remove previous values.
	unset( $old_values['consumer_email'], $old_values['consumer_key'], $old_values['site_is_pro'] );

	// Add other previous values.
	$values = array_merge( $old_values, $values );

	// Some cleanup.
	if ( empty( $old_values['wl_plugin_name'] ) || 'SecuPress' === $old_values['wl_plugin_name'] ) {
		unset( $old_values['wl_plugin_name'] );
	}
	if ( empty( $values['wl_plugin_name'] ) || 'SecuPress' === $values['wl_plugin_name'] ) {
		unset( $values['wl_plugin_name'] );
	}

	// Finally, save.
	secupress_update_options( $values );

	// White Label: trick the referrer for the redirection.
	if ( empty( $values['site_is_pro'] ) && ! empty( $values['wl_plugin_name'] ) ) {
		$old_slug = ! empty( $old_values['wl_plugin_name'] ) ? sanitize_title( $old_values['wl_plugin_name'] ) : 'secupress';
		$old_slug = 'page=' . $old_slug . '_settings';
		$new_slug = 'page=secupress_settings';

		if ( $old_slug !== $new_slug ) {
			$_REQUEST['_wp_http_referer'] = str_replace( $old_slug, $new_slug, wp_get_raw_referer() );
		}
	}

	/**
	 * Handle settings errors and return to settings page.
	 */
	// If no settings errors were registered add a general 'updated' message.
	if ( ! get_settings_errors( 'general' ) ) {
		if ( 'deactivate' === $action ) {
			add_settings_error( 'general', 'settings_updated', __( 'Your license has been successfully deactivated.', 'secupress' ), 'updated' );
		} else {
			add_settings_error( 'general', 'settings_updated', __( 'Your license has been successfully activated.', 'secupress' ), 'updated' );
		}
	}
	set_transient( 'settings_errors', get_settings_errors(), 30 );

	/**
	 * Redirect back to the settings page that was submitted.
	 */
	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( esc_url_raw( $goback ) );
	exit;
}


/**
 * Call our server to activate the Pro license.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $new_values The new settings.
 * @param (array) $old_values The old settings.
 *
 * @return (array) $new_values The new settings, some values may have changed.
 */
function secupress_global_settings_activate_pro_license( $new_values, $old_values ) {
	$api_old_values = secupress_array_merge_intersect( $old_values, array(
		'consumer_email' => '',
		'consumer_key'   => '',
		'site_is_pro'    => 0,
		'install_time'   => 0,
	) );

	if ( $new_values['install_time'] > 1 ) {
		$install_time = time() - $new_values['install_time'];
	} elseif ( -1 !== $new_values['install_time'] ) {
		$install_time = 0;
	} else {
		$install_time = -1;
	}

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'    => 'activate_pro_license',
		'user_email'   => $new_values['consumer_email'],
		'user_key'     => $new_values['consumer_key'],
		'install_time' => $install_time,
	) );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( $body = secupress_global_settings_api_request_succeeded( $response ) ) {
		// Success!
		$new_values['install_time'] = -1;
		$new_values['consumer_key'] = sanitize_text_field( $body->data->user_key );

		if ( ! empty( $body->data->site_is_pro ) ) {
			$new_values['site_is_pro'] = 1;
		} else {
			unset( $new_values['site_is_pro'] );
		}
	} else {
		// Keep old values.
		$new_values['consumer_email'] = $api_old_values['consumer_email'];
		$new_values['consumer_key']   = $api_old_values['consumer_key'];

		if ( ! $new_values['consumer_email'] || ! $new_values['consumer_key'] ) {
			unset( $new_values['consumer_email'], $new_values['consumer_key'], $new_values['site_is_pro'] );
		} elseif ( $api_old_values['site_is_pro'] ) {
			// Don't invalid the license because we couldn't reach our server or things like that.
			$new_values['site_is_pro'] = 1;
		} else {
			unset( $new_values['site_is_pro'] );
		}
	}

	return $new_values;
}


/**
 * Trigger a settings error if the given API request failed.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (mixed) $response The request response.
 *
 * @return (object|bool) The response body on success. False otherwise.
 */
function secupress_global_settings_api_request_succeeded( $response ) {

	if ( is_wp_error( $response ) ) {
		// The request couldn't be sent.
		add_settings_error( 'general', 'request_error', __( 'Something on your website is preventing the request to be sent.', 'secupress' ) );
		return false;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		// The server couldn't be reached. Maybe a server error or something.
		add_settings_error( 'general', 'server_error', __( 'Our server is not accessible at the moment, please try again later.', 'secupress' ) );
		return false;
	}

	$body = wp_remote_retrieve_body( $response );
	$body = @json_decode( $body );

	if ( ! is_object( $body ) ) {
		// The response is not a json.
		add_settings_error( 'general', 'server_bad_response', __( 'Our server returned an unexpected response and might be in error, please try again later or contact our support team.', 'secupress' ) );
		return false;
	}

	if ( empty( $body->success ) ) {
		// The response is an error.
		if ( ! empty( $body->data->code ) && 'invalid_api_credential' === $body->data->code ) {

			add_settings_error( 'general', 'response_error', __( 'There is a problem with your license key, please contact our support team.', 'secupress' ) );

		} elseif ( ! empty( $body->data->code ) && 'invalid_email' === $body->data->code ) {

			add_settings_error( 'general', 'response_error', __( 'The email address is invalid.', 'secupress' ) );

		} elseif ( ! empty( $body->data->code ) && 'invalid_customer' === $body->data->code ) {

			add_settings_error( 'general', 'response_error', __( 'This email address is not in our database.', 'secupress' ) );

		} elseif ( ! empty( $body->data->code ) && 'no_activations_left' === $body->data->code ) {

			add_settings_error( 'general', 'response_error', __( 'You\'ve used as many as your license allows, you may want to upgrade your license to add more sites.', 'secupress' ) );

		} else {
			add_settings_error( 'general', 'response_error', __( 'Something may be wrong with your license, please take a look at your account or contact our support team.', 'secupress' ) );
		}

		return false;
	}

	return $body;
}


/**
 * Call our server to deactivate the Pro license.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (array) $new_values The new settings.
 *
 * @return (array) $new_values The new settings, the email and the key have been removed.
 */
function secupress_global_settings_deactivate_pro_license( $new_values ) {

	$url = SECUPRESS_WEB_MAIN . 'key-api/1.0/?' . http_build_query( array(
		'sp_action'    => 'deactivate_pro_license',
		'user_email'   => $new_values['consumer_email'],
		'user_key'     => $new_values['consumer_key'],
	) );

	unset( $new_values['consumer_email'], $new_values['consumer_key'] );

	$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

	if ( is_wp_error( $response ) ) {
		// The request couldn't be sent.
		$message = __( 'Something on your website is preventing the request to be sent.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		add_settings_error( 'general', 'request_error', $message );
		return $new_values;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		// The server couldn't be reached. Maybe a server error or something.
		$message = __( 'Our server is not accessible at the moment.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		add_settings_error( 'general', 'server_error', $message );
		return $new_values;
	}

	$body = wp_remote_retrieve_body( $response );
	$body = @json_decode( $body );

	if ( ! is_object( $body ) ) {
		// The response is not a json.
		$message = __( 'Our server returned an unexpected response and might be in error.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		add_settings_error( 'general', 'server_bad_response', $message );
		return $new_values;
	}

	if ( empty( $body->success ) ) {
		// Didn't succeed.
		$message = __( 'Our server returned an error.', 'secupress' );
		$message = secupress_global_settings_pro_license_deactivation_error_message( $message );
		add_settings_error( 'general', 'response_error', $message );
	}

	return $new_values;
}


/**
 * Given a message, add a sentense to it with a link to the user account on our website.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (string) The message with a link to our website appended.
 */
function secupress_global_settings_pro_license_deactivation_error_message( $message ) {
	if ( secupress_is_white_label() ) {
		// White-labelled, don't add a link to our website.
		return $message;
	}

	/** Translators: this is the slug (part of the URL) of the account page on secupress.me, like in https://secupress.me/account/, it must not be translated if the page doesn't exist. */
	$secupress_message = esc_url( SECUPRESS_WEB_MAIN . _x( 'account', 'URL slug', 'secupress' ) . '/' );
	$secupress_message = sprintf(
		/** Translators: %s is a link to the "SecuPress account". */
		__( 'Please deactivate this site from your %s (the "Manage Sites" link in your license details).', 'secupress' ),
		'<a target="_blank" href="' . $secupress_message . '">' . __( 'SecuPress account', 'secupress' ) . '</a>'
	);

	if ( is_rtl() ) {
		$message = $secupress_message . ' ' . $message;
	} else {
		$message .= ' ' . $secupress_message;
	}

	return $message;
}
