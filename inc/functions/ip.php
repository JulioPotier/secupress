<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get the IP address of the current user.
 *
 * @since 1.4.3 Add $priority param
 * @since 1.0
 *
 * @param (string) $priority Contains a key from $keys to be read first.
 * @return (string)
 */
function secupress_get_ip( $priority = null ) {
	// Find the best order.
	$keys = [
		'HTTP_CF_CONNECTING_IP', // CF = CloudFlare.
		'HTTP_CLIENT_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	];

	if ( ! is_null( $priority ) ) {
		array_unshift( $keys, $priority );
	}

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
		), array( 'force_die' => true ) );
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


/**
 * Returns if the user-agent is a fake bot or not.
 *
 * @since 1.4.2 Add $test param + revamp
 * @since 1.4
 *
 * @param (bool) $test Set to TRUE to just get the googlebot hostname test result (transient enabled).
 * @return (bool) true mean the IP is a good bot, false is a fake bot.
 *
 * @author Julio Potier
 **/
function secupress_check_bot_ip( $test = false ) {
	// static $test_result;

	// if ( $test && isset( $test_result ) ) {
	// 	return $test_result;
	// }
	// if ( $test && ( false !== ( $test_result = get_site_transient( 'secupress-test-hostname' ) ) ) ) {
	// 	return $test_result;
	// }

	if ( ! $test ) {
		$ip         = secupress_get_ip( 'REMOTE_ADDR' );
	} else {
		$ip         = '66.249.66.83'; // GoogleBot.
	}
	$hostname_addr  = gethostbyaddr( $ip );
	$real_ip        = gethostbyname( $hostname_addr );
	try {
		$hostname_fork  = `host $ip`;
	} catch (Exception $e) {
		$hostname_fork = false;
	}
	$hostname       = is_string( $hostname_addr ) && ! secupress_ip_is_valid( $hostname_addr ) ? $hostname_addr : $hostname_fork;
	$hostname       = is_string( $hostname ) ? explode( ' ', $hostname ) : [];
	$hostname       = end( $hostname );
	$user_agent     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';

	if ( true === $test ) {
		$test_result = (int) preg_match( '/google/i', $hostname );
		set_site_transient( 'secupress-test-hostname', $test_result, WEEK_IN_SECONDS );
		return (bool) $test_result;
	}

	if ( preg_match( '/google/i', $user_agent ) && ( preg_match( '/google/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/bingbot|msnbot/i', $user_agent ) && ( preg_match( '/msn/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/facebot|facebook/i', $user_agent ) && ( preg_match( '/facebook/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/slurp/i', $user_agent ) && ( preg_match( '/yahoo/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/baiduspider/i', $user_agent ) && ( preg_match( '/baidu/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/yandexbot/i', $user_agent ) && ( preg_match( '/yandex/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/duckduckbot/i', $user_agent ) && ( preg_match( '/duckduck/i', $hostname ) ) ) {
		return true;
	}
	if ( preg_match( '/ia_archiver/i', $user_agent ) && ( preg_match( '/alexa/i', $hostname ) ) ) {
		return true;
	}

	return false;
}
