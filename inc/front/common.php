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
	$ban_ips             = get_option( SECUPRESS_BAN_IP );
	$bad_logins_time_ban = secupress_get_module_option( 'bad_logins_time_ban', 5, 'users_login' );
	$refresh_htaccess    = false;

	// if we got banned ips
	if ( is_array( $ban_ips ) && count( $ban_ips ) ) {

		foreach ( $ban_ips as $IP => $time ) {
			// purge the expired banned IPs
			if ( ( $time + ( $bad_logins_time_ban * 60 ) ) < time() ) {
				unset( $ban_ips[ $IP ] );
				$refresh_htaccess = true;
			}
		}

		update_option( SECUPRESS_BAN_IP, $ban_ips );

		if ( $refresh_htaccess ) {
			wp_load_alloptions();
			secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
		}

		// check if the IP is still in the array
		$IP = secupress_get_ip();

		if ( array_key_exists( $IP, $ban_ips ) ) {
			$msg = sprintf( __( 'Your IP address <code>%1$s</code> have been banned for <b>%2$d</b> minute(s), please do not retry until.', 'secupress' ), esc_html( $IP ), $bad_logins_time_ban );
			secupress_die( $msg );
		}

	} else {
		delete_option( SECUPRESS_BAN_IP );
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
	global $current_user, $pagenow;
	$current_user = wp_get_current_user();

	$current_user_ID = $current_user->ID;
	if ( empty( $_POST ) && ( ! isset( $pagenow ) || 'admin-post.php' != $pagenow ) && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_AUTOSAVE' ) && ! defined( 'DOING_CRON' ) && 
		is_user_logged_in() && $data = get_transient( 'secupress-rename-admin-username' )
	) {
		delete_transient( 'secupress-rename-admin-username' );
		if ( ! is_array( $data ) || ! isset( $data['ID'], $data['username'] ) || $current_user->ID != $data['ID'] || 'admin' != $current_user->user_login ) {
			return;
		}
		global $wpdb;
		$wpdb->update( $wpdb->users, array( 'user_login' => $data['username'] ), array( 'user_login' => 'admin' ) );
		// Current user auth cookie is now invalid, log in again is mandatory
		
		wp_clear_auth_cookie();
		wp_destroy_current_session();

		$token = md5( time() );
		set_transient( 'secupress_auto_login_' . $token, $data['username'] );
		wp_safe_redirect( add_query_arg( 'secupress_auto_login_token', $token, secupress_get_current_url( 'raw' ) ) );
		die();
	}
}

add_action( 'plugins_loaded', 'secupress_rename_admin_username_login', 60 );
/**
 * Will rename the "admin" account after the rename-admin-username manual fix
 *
 * @since 1.0 
 * @return void
 **/
function secupress_rename_admin_username_login() {
	if ( isset( $_GET['secupress_auto_login_token'] ) ) {
		$username = get_transient( 'secupress_auto_login_' . $_GET['secupress_auto_login_token'] );
		if ( $username ) {
			delete_transient( 'secupress_auto_login_' . $_GET['secupress_auto_login_token'] );

			add_filter( 'authenticate', '__secupress_give_him_a_user', 1, 2 );
			$user = wp_signon( array( 'user_login' => $username ) );
			remove_filter( 'authenticate', '__secupress_give_him_a_user', 1, 2 );
			
			if ( is_a( $user, 'WP_User' ) ) {
				wp_set_current_user( $user->ID, $user->user_login );
				wp_set_auth_cookie( $user->ID );
			}

			secupress_fixit( 'Admin_User' );
			secupress_scanit( 'Admin_User' );

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