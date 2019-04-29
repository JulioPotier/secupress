<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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

	$test_name        = esc_attr( $_GET['test'] );
	$for_current_site = ! empty( $_GET['for-current-site'] );
	$site_id          = $for_current_site && ! empty( $_GET['site'] ) ? '-' . absint( $_GET['site'] ) : '';

	secupress_check_user_capability( $for_current_site );
	secupress_check_admin_referer( 'secupress_scanner_' . $test_name . $site_id );

	$doing_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;
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
		wp_die( 'Cheatin\' uh?' );
	}
	$_CLEAN          = [];
	$_CLEAN['email'] = $_POST['email'];
	$user            = get_user_by( 'email', $_CLEAN['email'] );
	if ( ! $user || ! user_can( $user, 'manage_options' ) ) {
		wp_die( 'Cheatin\' uh?' );
	}
	$url_remember = wp_login_url();
	$token        = strtolower( wp_generate_password( 10, false ) );
	set_transient( 'secupress_unlock_admin_key', $token, DAY_IN_SECONDS );
	$url_remove   = add_query_arg( '_wpnonce', $token, admin_url( 'admin-post.php?action=secupress_deactivate_module&module=move-login' ) );

	$subject      = __( '###SITENAME### – Unlock an administrator', 'secupress' );
	$message      = sprintf( __( 'Hello %1$s, it seems you are locked out from your website ###SITENAME###.<br><br>You can now click to go to the login page or deactivate the Move Login module.<br><br>%2$s<br>%3$s<br><br>Have a nice day!', 'secupress' ),
							$user->nicename,
							'<a href="' . $url_remember . '">' . $url_remember . '</a>',
							'<a href="' . $url_remove . '">' . $url_remove . '</a> ' . __( '(Valid 1 day)', 'secupress' )
					);
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
		wp_die( 'Cheatin\' uh?' );
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
		wp_die( 'Cheatin\' uh?' );
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
 * Will reset the settings like a fresh install
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
