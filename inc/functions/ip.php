<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get the IP address of the current user.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_ip() {
	// Find the best order.
	$keys = array(
		'HTTP_CF_CONNECTING_IP', // CF = CloudFlare.
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
			$ip = explode( ',', $_SERVER[ $key ], 2 );
			$ip = reset( $ip );

			if ( false !== secupress_ip_is_valid( $ip ) ) {
				/**
				 * Filter the valid IP address.
				 *
				 * @since 1.0
				 *
				 * @param (string) $ip The IP address.
				 */
				return apply_filters( 'secupress.ip.get_ip', $ip );
			}
		}
	}

	/**
	 * Filter the default IP address.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip The IP address.
	 */
	return apply_filters( 'secupress.ip.default_ip', '0.0.0.0' );
}


/**
 * Tell if an IP address is valid.
 *
 * @since 1.0
 *
 * @param (string) $ip An IP address.
 *
 * @return (string|bool) The IP address if valid. False otherwise.
 */
function secupress_ip_is_valid( $ip ) {
	if ( ! $ip || ! is_string( $ip ) ) {
		return false;
	}

	$ip = trim( $ip );
	return filter_var( $ip, FILTER_VALIDATE_IP );
}


/**
 * Tell if an IP address is whitelisted.
 *
 * @since 1.0
 *
 * @param (string) $ip An IP address. If not provided, the current IP by default.
 *
 * @return (bool).
 */
function secupress_ip_is_whitelisted( $ip = null ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( ! $ip = secupress_ip_is_valid( $ip ) ) {
		return false;
	}

	// Some hardcoded IPs that are always whitelisted.
	$whitelist = array(
		'::1'                   => 1,
		'0.0.0.0'               => 1,
		'127.0.0.1'             => 1,
		'37.187.85.82'          => 1, // WPRocketbot.
		'37.187.58.236'         => 1, // WPRocketbot.
		'167.114.234.234'       => 1, // WPRocketbot.
	);

	if ( isset( $_SERVER['SERVER_ADDR'] ) ) {
		$whitelist[ $_SERVER['SERVER_ADDR'] ] = 1;
	}

	if ( isset( $whitelist[ $ip ] ) ) {
		return true;
	}

	// The IPs from the settings page.
	$whitelist = secupress_get_module_option( 'banned-ips_whitelist', '', 'logs' );
	$whitelist = explode( "\n", $whitelist );
	$whitelist = array_flip( $whitelist );

	/**
	 * Filter the IPs whitelist.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $whitelist The whitelist. IPs are the array keys.
	 * @param (string) $ip        The IP address.
	 */
	$whitelist = apply_filters( 'secupress.ip.ips_whitelist', $whitelist, $ip );

	return isset( $whitelist[ $ip ] );
}


/**
 * Ban an IP address if not whitelisted.
 * Will add the IP to the list of banned IPs. Will maybe write the IPs in the `.htaccess` file. Will maybe forbid access to the user by displaying a message.
 *
 * @since 1.0
 *
 * @param (int)    $time_ban Ban duration in minutes. Only used in the message.
 * @param (string) $ip       The IP to ban.
 * @param (bool)   $die      True to forbid access to the user by displaying a message.
 */
function secupress_ban_ip( $time_ban = 5, $ip = null, $die = true ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( secupress_ip_is_whitelisted( $ip ) ) {
		return;
	}

	$time_ban = (int) $time_ban > 0 ? (int) $time_ban : 5;
	$ban_ips  = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips  = is_array( $ban_ips ) ? $ban_ips : array();

	$ban_ips[ $ip ] = time();

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/**
	 * Fires once a IP is banned.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip      The IP banned.
	 * @param (array)  $ban_ips The list of IPs banned (keys) and the time they were banned (values).
	 */
	do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

	if ( secupress_write_in_htaccess_on_ban() ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	if ( $die ) {
		secupress_die( sprintf(
			_n( 'Your IP address %1$s has been banned for %2$s minute, please do not retry until then.', 'Your IP address %1$s has been banned for %2$s minutes, please do not retry until then.', $time_ban, 'secupress' ),
			'<code>' . esc_html( $ip ) . '</code>',
			'<strong>' . number_format_i18n( $time_ban ) . '</strong>'
		) );
	}
}


/**
 * Tell if rules should be inserted in the `.htaccess` file when an IP in banned.
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_write_in_htaccess_on_ban() {
	/**
	 * Filter to write in the file.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $write False by default.
	 */
	return apply_filters( 'secupress.ban.write_in_htaccess', false );
}
