<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'plugins_loaded', 'secupress_check_ban_ips' );
/**
 * Will add or remove banned IPs
 *
 * @since 1.0
 * @return void
 **/
function secupress_check_ban_ips() {
	$ban_ips                   = get_site_option( SECUPRESS_BAN_IP );
	$login_protection_time_ban = secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' );
	$refresh_htaccess          = false;

	// if we got banned ips
	if ( is_array( $ban_ips ) && count( $ban_ips ) ) {

		foreach ( $ban_ips as $IP => $time ) {
			// purge the expired banned IPs
			if ( ( $time + ( $login_protection_time_ban * 60 ) ) < time() ) {
				unset( $ban_ips[ $IP ] );
				$refresh_htaccess = true;
			}
		}

		update_site_option( SECUPRESS_BAN_IP, $ban_ips );

		if ( $refresh_htaccess ) {
			wp_load_alloptions();
			secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
		}

		// check if the IP is still in the array
		$IP = secupress_get_ip();

		if ( array_key_exists( $IP, $ban_ips ) ) {
			$msg = sprintf( __( 'Your IP address <code>%1$s</code> have been banned for <b>%2$d</b> minute(s), please do not retry until.', 'secupress' ), esc_html( $IP ), $login_protection_time_ban );
			secupress_die( $msg );
		}

	} elseif ( false !== $ban_ips ) {
		delete_site_option( SECUPRESS_BAN_IP );
	}
}


add_action( 'plugins_loaded', 'secupress_rename_admin_username_logout', 50 );
/**
 * Will rename the "admin" account after the rename-admin-username manual fix
 *
 * @since 1.0
 * @return void
 **/
function secupress_rename_admin_username_logout() {
	global $current_user, $pagenow, $wpdb;

	$current_user    = wp_get_current_user();
	$current_user_ID = $current_user->ID;

	if ( empty( $_POST ) && ( ! isset( $pagenow ) || 'admin-post.php' != $pagenow ) && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_AUTOSAVE' ) && ! defined( 'DOING_CRON' ) &&
		is_user_logged_in() && $data = secupress_get_site_transient( 'secupress-rename-admin-username' )
	) {
		secupress_delete_site_transient( 'secupress-rename-admin-username' );

		if ( ! is_array( $data ) || ! isset( $data['ID'], $data['username'] ) || $current_user->ID != $data['ID'] || 'admin' != $current_user->user_login ) {
			return;
		}

		$wpdb->update( $wpdb->users, array( 'user_login' => $data['username'] ), array( 'user_login' => 'admin' ) );
		// Current user auth cookie is now invalid, log in again is mandatory

		wp_clear_auth_cookie();
		wp_destroy_current_session();

		$token = md5( time() );
		secupress_set_site_transient( 'secupress_auto_login_' . $token, array( $data['username'], 'Admin_User' ) );

		// Store a good scan result.
		secupress_set_site_transient( 'secupress_scan_admin_user', array(
			'msgs'   => array(
				0 => array( '<em>admin</em>' ),
			),
			'status' => 'good',
		) );

		wp_safe_redirect( add_query_arg( 'secupress_auto_login_token', $token, secupress_get_current_url( 'raw' ) ) );
		die();
	}
}

add_action( 'plugins_loaded', 'secupress_add_cookiehash_muplugin', 50 );
/**
 * Will create a mu plugin to modify the COOKIEHASH constant
 *
 * @since 1.0
 * @return void
 **/
function secupress_add_cookiehash_muplugin() {
	global $current_user, $pagenow, $wpdb;

	$current_user    = wp_get_current_user();
	$current_user_ID = $current_user->ID;

	if ( empty( $_POST ) && ( ! isset( $pagenow ) || 'admin-post.php' != $pagenow ) && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_AUTOSAVE' ) && ! defined( 'DOING_CRON' ) &&
		is_user_logged_in() && $data = secupress_get_site_transient( 'secupress-add-cookiehash-muplugin' )
	) {
		secupress_delete_site_transient( 'secupress-add-cookiehash-muplugin' );

		if ( ! is_array( $data ) || ! isset( $data['ID'], $data['username'] ) || $current_user->ID != $data['ID'] ) {
			return;
		}

		$contents  = '<?php // Added by SecuPress' . PHP_EOL;
		$contents .= 'define( \'COOKIEHASH\', md5( __FILE__ . \'' . wp_generate_password( 64 ) . '\' ) );';
		if ( secupress_create_mu_plugin( 'COOKIEHASH_' . uniqid(), $contents ) ) {
			wp_clear_auth_cookie();
			wp_destroy_current_session();

			$token = md5( time() );
			secupress_set_site_transient( 'secupress_auto_login_' . $token, array( $data['username'], 'WP_Config' ) );

			wp_safe_redirect( add_query_arg( 'secupress_auto_login_token', $token, secupress_get_current_url( 'raw' ) ) );
			die();
		}
	}
}

add_action( 'plugins_loaded', 'secupress_add_salt_muplugin', 50 );
/**
 * Will create a mu plugin to early set the salt keys
 *
 * @since 1.0
 * @return void
 **/
function secupress_add_salt_muplugin() {
	global $current_user, $pagenow, $wpdb;

	$current_user    = wp_get_current_user();
	$current_user_ID = $current_user->ID;
	if ( ! defined( 'SECUPRESS_SALT_KEYS_ACTIVE' ) && empty( $_POST ) && ( ! isset( $pagenow ) || 'admin-post.php' != $pagenow ) && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_AUTOSAVE' ) && ! defined( 'DOING_CRON' ) &&
		is_user_logged_in() && $data = secupress_get_site_transient( 'secupress-add-salt-muplugin' )
	) {
		secupress_delete_site_transient( 'secupress-add-salt-muplugin' );

		$wpconfig_filename = secupress_find_wpconfig_path();
		if ( ! is_writable( $wpconfig_filename ) || ! is_array( $data ) || ! isset( $data['ID'], $data['username'] ) || $current_user->ID != $data['ID'] ) {
			return;
		}

		$keys = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT', );

		foreach ( $keys as $constant ) {
			secupress_replace_content( $wpconfig_filename, "/define\(.*('" . $constant . "'|\"" . $constant . "\").*,/", "/*Commented by SecuPress*/ // $0" );
		}

		$alicia_keys = file_get_contents( SECUPRESS_INC_PATH . 'data/salt-keys.phps' );
		$alicia_keys = str_replace( array( '{{HASH1}}', '{{HASH2}}' ), array( wp_generate_password( 64, true, true ), wp_generate_password( 64, true, true ) ), $alicia_keys );

		if ( ! $alicia_keys || ! secupress_create_mu_plugin( 'salt_keys_' . uniqid(), $alicia_keys ) ) {
			return;
		}

		wp_clear_auth_cookie();
		wp_destroy_current_session();

		foreach ( $keys as $constant ) {
			delete_site_option( $constant );
		}

		$token = md5( time() );
		secupress_set_site_transient( 'secupress_auto_login_' . $token, array( $data['username'], 'Salt_Keys' ) );

		wp_safe_redirect( add_query_arg( 'secupress_auto_login_token', $token, secupress_get_current_url( 'raw' ) ) );
		die();
	}
}

add_action( 'plugins_loaded', 'secupress_auto_username_login', 60 );
/**
 * Will autologin the user found in the transient 'secupress_auto_login_' . $_GET['secupress_auto_login_token']
 *
 * @since 1.0
 * @return void
 */

function secupress_auto_username_login() {

	if ( isset( $_GET['secupress_auto_login_token'] ) ) {

		list( $username, $action ) = secupress_get_site_transient( 'secupress_auto_login_' . $_GET['secupress_auto_login_token'] );

		secupress_delete_site_transient( 'secupress_auto_login_' . $_GET['secupress_auto_login_token'] );

		if ( $username ) {

			add_filter( 'authenticate', '__secupress_give_him_a_user', 1, 2 );
			$user = wp_signon( array( 'user_login' => $username ) );
			remove_filter( 'authenticate', '__secupress_give_him_a_user', 1, 2 );

			if ( is_a( $user, 'WP_User' ) ) {
				wp_set_current_user( $user->ID, $user->user_login );
				wp_set_auth_cookie( $user->ID );
			}

			if ( $action ) {
				secupress_scanit( $action );
			}
			wp_safe_redirect( remove_query_arg( 'secupress_auto_login_token', secupress_get_current_url( 'raw' ) ) );
			die();
		}
	}
}

/**
 * Used in secupress_rename_admin_username_login() to force a user when auto authenticating
 *
 * @return WP_User/false
 * @since 1.0
 **/
function __secupress_give_him_a_user( $user, $username ) {
	return get_user_by( 'login', $username );
}


add_action( 'plugins_loaded', 'secupress_downgrade_author_administrator', 70 );
/**
 * Admin As Author fix: a new Administrator account has been created, now we need to downgrade the old one.
 *
 * @since 1.0
 * @return void
 **/
function secupress_downgrade_author_administrator() {
	if ( ! is_admin() ) {
		return;
	}

	// "{$new_user_id}|{$old_user_id}"
	$data = secupress_get_site_transient( 'secupress-admin-as-author-administrator' );

	// Nope.
	if ( ! $data ) {
		return;
	}

	if ( ! is_string( $data ) ) {
		// Dafuk
		secupress_delete_site_transient( 'secupress-admin-as-author-administrator' );
		return;
	}

	list( $new_user_id, $old_user_id ) = array_map( 'absint', explode( '|', $data ) );

	if ( ! isset( $new_user_id, $old_user_id ) || ! $new_user_id || ! $old_user_id || $new_user_id === $old_user_id ) {
		// Dafuk
		secupress_delete_site_transient( 'secupress-admin-as-author-administrator' );
		return;
	}

	if ( ! file_exists( secupress_class_path( 'scan', 'Admin_As_Author' ) ) ) {
		// Dafuk
		secupress_delete_site_transient( 'secupress-admin-as-author-administrator' );
		return;
	}

	// These aren't the droids you're looking for.
	if ( $new_user_id !== get_current_user_id() ) {
		return;
	}

	if ( ! user_can( $new_user_id, 'administrator' ) || ! user_can( $old_user_id, 'administrator' ) ) {
		// Hey! What did you do?!
		secupress_delete_site_transient( 'secupress-admin-as-author-administrator' );
		return;
	}

	// The old account (the one with Posts).
	$user = get_user_by( 'id', $old_user_id );

	if ( ! $user ) {
		continue;
	}

	secupress_require_class( 'scan' );
	secupress_require_class( 'scan', 'Admin_As_Author' );

	$role = SecuPress_Scan_Admin_As_Author::get_new_role();

	/*
	 * No suitable user role: create one (who the fuck deleted it?!).
	 */
	if ( ! $role ) {
		$role = SecuPress_Scan_Admin_As_Author::create_editor_role();

		if ( ! $role ) {
			// the user role could not be created.
			return;
		}

		$role = $role['name'];
	}

	// Finally, change the user role.
	$user->remove_role( 'administrator' );
	$user->add_role( $role );

	// Update scan result.
	secupress_scanit( 'Admin_As_Author' );

	// Bye bye!
	secupress_delete_site_transient( 'secupress-admin-as-author-administrator' );
}

add_action( 'secupress_loaded', '__secupress_process_file_monitoring_tasks' );
function __secupress_process_file_monitoring_tasks() {
	if ( ! is_admin() || false === ( get_site_transient( 'secupress_toggle_file_scan' ) ) ) {
		return;
	}
	/* https://github.com/A5hleyRich/wp-background-processing v1.0 */
	secupress_require_class( 'Admin', 'wp-async-request' );
	secupress_require_class( 'Admin', 'wp-background-process' );
	/* */
	secupress_require_class( 'Admin', 'file-monitoring' );

	SecuPress_File_Monitoring::get_instance();
}
