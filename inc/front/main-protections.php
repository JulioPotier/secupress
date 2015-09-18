<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'plugins_loaded', 'secupress_check_ban_ips' );

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
			secupress_write_htaccess( 'ban_ip' );
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
