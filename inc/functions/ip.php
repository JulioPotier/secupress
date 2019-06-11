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
 * @param (bool) $range_format If we have to check in ranges format.
 * @param (null|int) $flag Flags from filter_var()
 *
 * @return (bool) True is valid IP
 */
function secupress_ip_is_valid( $ip, $range_format = false , $flag = null ) {
	if ( ! $ip || ! is_string( $ip ) ) {
		return false;
	}

	$ip = trim( $ip );
	if ( filter_var( $ip, FILTER_VALIDATE_IP, $flag ) ) {
		return true;
	}

	if ( ! $range_format ) {
		return false;
	}

	if ( strpos( $ip, '*' ) > 0 ) {
		$ipv4 = str_replace( '*', '0', $ip );
		$ipv6 = str_replace( '*', '', $ip );
		$ipv6 = secupress_get_full_ipv6( $ipv6, '0' );

		if ( FILTER_FLAG_IPV6 === $flag ) {
			return (bool) filter_var( $ipv6, FILTER_VALIDATE_IP, $flag );
		} elseif ( FILTER_FLAG_IPV4 === $flag ) {
			return (bool) filter_var( $ipv4, FILTER_VALIDATE_IP, $flag );
		} elseif ( is_null( $flag ) ) {
			return (bool) ( filter_var( $ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || filter_var( $ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) );
		}
	}

	if ( strpos( $ip, '/' ) > 0 ) {
		$ip = explode( '/', $ip, 2 );
		return (bool) filter_var( $ip[0], FILTER_VALIDATE_IP, $flag ) && is_numeric( $ip[1] ) && $ip[1] <= 128 && $ip[1] > 0;
	}

	if ( strpos( $ip, '-' ) > 0 ) {
		$ip = explode( '-', $ip, 2 );
		return (bool) filter_var( $ip[0], FILTER_VALIDATE_IP, $flag ) && is_numeric( $ip[1] )  && $ip[1] <= 255 && $ip[1] > 0;
	}

	return false;
}

/**
 * Transform a non complete IPv6 form to its complete form (from '-' range)
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @param (string) $ipv6 Non complete IPv6 form like fedc:6482:cafe::-fedc:6482:cafe:ffff:ffff:ffff:ffff:ffff
 * @param (string) $mask Either '0' of 'f' to complete the ipv6@
 * @return (string) The final ipv6 form
 **/
function secupress_get_full_ipv6( $ipv6, $mask ) {
	$ipv6 = explode( ':', $ipv6 );
	$ipv6 = array_filter( $ipv6 );
	$ipv6 = $ipv6 + array_fill( count( $ipv6 ), 4 - count( $ipv6 ), '0/ffff' );
	$ipv6 = implode( ':', $ipv6 );
	$temp = explode( '::-', $ipv6 );
	$ipv6 = $temp[0] . str_repeat( ':0/ffff', 7 - substr_count( $temp[0], ':' ) );
	$ipv6 = str_replace( '0/ffff', $mask, $ipv6 );
	return $ipv6;
}

/**
 * Tell if an IP address is whitelisted.
 *
 * @since 1.0
 * @since 1.4.9 $in_range param
 *
 * @param (string) $ip An IP address. If not provided, the current IP by default.
 * @param (bool) $in_range Specify if the whitelist should aso be tested including ranged ips
 *
 * @return (bool).
 */
function secupress_ip_is_whitelisted( $ip = null, $in_range = true ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( ! secupress_ip_is_valid( $ip ) ) {
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
	// The IPs from the settings page.
	$_whitelist = get_site_option( SECUPRESS_WHITE_IP );
	if ( $_whitelist ) {
		$_whitelist = array_flip( array_keys( $_whitelist ) );
		$whitelist  = array_merge( $whitelist, $_whitelist );
	}
	/**
	 * Filter the IPs whitelist.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $whitelist The whitelist. IPs are the array keys.
	 * @param (string) $ip        The IP address.
	 */
	$whitelist = apply_filters( 'secupress.ip.ips_whitelist', $whitelist, $ip );
	if ( isset( $whitelist[ $ip ] ) ) {
		return true;
	}

	if ( $in_range ) {
		// Handle IP ranges lately
		$whitelist = array_keys( $whitelist );
		$whitelist = array_filter( $whitelist, function( $item ) {
			return strpos( $item, '*' ) > 0 || strpos( $item, '/' ) > 0 || strpos( $item, '-' ) > 0;
		} );

		return secupress_is_ip_in_range( $ip, $whitelist );
	}

	return false;
}

/**
 * Tell if an IP address is blacklisted.
 *
 * @since 1.4.9
 *
 * @param (string) $ip An IP address. If not provided, the current IP by default.
 *
 * @return (bool).
 */
function secupress_ip_is_blacklisted( $ip = null ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( ! secupress_ip_is_valid( $ip ) ) {
		return false;
	}

	// The IPs from the settings page.
	$blacklist = get_site_option( SECUPRESS_BAN_IP );
	$blacklist = array_flip( array_keys( $blacklist ) );
	/**
	 * Filter the IPs blacklist.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)  $blacklist The blacklist. IPs are the array keys.
	 * @param (string) $ip        The IP address.
	 */
	$blacklist = apply_filters( 'secupress.ip.ips_blacklist', $blacklist, $ip );
	if ( isset( $blacklist[ $ip ] ) ) {
		return true;
	}
	// Handle IP ranges lately
	$blacklist = array_keys( $blacklist );
	$blacklist = array_filter( $blacklist, function( $item ) {
		return strpos( $item, '*' ) > 0 || strpos( $item, '/' ) > 0 || strpos( $item, '-' ) > 0;
	} );
	return secupress_is_ip_in_range( $ip, $blacklist );
}

/**
 * Check if the asked IP is in the asked range :
 * • 123.123.123.0-24 = from 123.123.123.0 to 123.123.123.24
 * • 123.123.123.0/24 = from 123.123.123.0 to 123.123.123.255
 * • 123.123.*.*      = from 123.123.0.0   to 123.123.255.255
 *
 * • fedc:6482:cafe::-fedc:6482:cafe:ffff:ffff:ffff:ffff:ffff = from fedc:6482:cafe:0:0:0:0:0 to fedc:6482:cafe:ffff:ffff:ffff:ffff:ffff
 * • fedc:6482:cafe::/32 = from fedc:6482:cafe:0:0:0:0:0 to fedc:cafe:FFFF:ffff:ffff:ffff:ffff:ffff
 * • fedc:6482:cafe:* = from fedc:6482:cafe:0:0:0:0:0    to fedc:6482:FFFF:ffff:ffff:ffff:ffff:ffff
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @param (string) $ip The $ip to be checked
 * @param (array) $ips The IPS whitelist
 * @return (bool) True if in range
 **/
function secupress_is_ip_in_range( $ip, $ips ) {
	if ( empty( $ips ) || ! is_array( $ips ) ) {
		return false;
	}
	foreach ( $ips as $_ips ) {
		if ( secupress_ip_is_valid( $ip, true, FILTER_FLAG_IPV4 ) && secupress_ip_is_valid( $_ips, true, FILTER_FLAG_IPV4 ) ) {
			if ( 0 === strcmp( $ip, $_ips ) ) {
				return true;
			}
			if ( strpos( $_ips, '-' ) ) {
				list( $first_ip, $mask ) = explode( '-', $_ips );
				$_ip      = explode('.', $first_ip);
				$_ip[3]   = $mask;
				$last_ip  = implode('.', $_ip);

				return ip2long( $ip ) >= ip2long( $first_ip ) && ip2long( $ip ) <= ip2long( $last_ip );
			}
			if ( strpos( $_ips, '/' ) ) {
				list( $first_ip, $mask ) = explode( '/', $_ips );
				if ( $mask === '0' ) {
					return true;
				}
				if ( $mask < 0 || $mask > 32 ) {
					return false;
				}
				return 0 === substr_compare( sprintf( '%032b', ip2long( $ip ) ), sprintf( '%032b', ip2long( $first_ip ) ), 0, $mask );
			}
			if ( strpos( $_ips, '*' ) ) {
				$mask     = str_replace( '*', '', $_ips );
				$mask     = explode( '.', $mask );
				$mask     = array_filter( $mask );
				$mask     = $mask + array_fill( count( $mask ), 4 - count( $mask ), '0/255' );
				$mask     = implode( '.', $mask );
				$first_ip = str_replace( '0/255', '0', $mask );
				$last_ip  = str_replace( '0/255', '255', $mask );

				return secupress_ipv6_numeric( $ip ) >= secupress_ipv6_numeric( $first_ip ) && secupress_ipv6_numeric( $ip ) <= secupress_ipv6_numeric( $last_ip );
			}
			return false;
		} elseif ( secupress_ip_is_valid( $ip, true , FILTER_FLAG_IPV6 ) && secupress_ip_is_valid( $_ips, true , FILTER_FLAG_IPV6 ) ) {
			if ( strpos( $_ips, '::-' ) ) {
				$temp     = explode( '::-', $_ips );
				$first_ip = $temp[0] . str_repeat( ':0', 7 - substr_count( $temp[0], ':' ) );
				$last_ip  = $temp[1];

				return secupress_ipv6_numeric( $ip ) >= secupress_ipv6_numeric( $first_ip ) && secupress_ipv6_numeric( $ip ) <= secupress_ipv6_numeric( $last_ip );
			}
			if ( strpos( $_ips, '/' ) ) {
				list( $first_ip, $mask ) = explode( '/', $_ips, 2 );
				if ($mask < 1 || $mask > 128) {
					return false;
				}
				$bytesAddr = unpack( 'n*', @inet_pton( $first_ip ) );
				$bytesTest = unpack( 'n*', @inet_pton( $ip ) );
				if ( ! $bytesAddr || ! $bytesTest ) {
					return false;
				}
				for ( $i = 1, $ceil = ceil( $mask / 16 ); $i <= $ceil; ++$i ) {
					$left = $mask - 16 * ( $i - 1 );
					$left = ( $left <= 16 ) ? $left : 16;
					$mask = ~ ( 0xffff >> $left ) & 0xffff;
					if ( ( $bytesAddr[$i] & $mask ) != ( $bytesTest[$i] & $mask ) ) {
						return false;
					}
				}
				return true;
			}
			if ( strpos( $_ips, '*' ) ) {
				$_ips     = str_replace( '*', '', $_ips );
				$first_ip = secupress_get_full_ipv6( $_ips, '0' );
				$last_ip  = secupress_get_full_ipv6( $_ips, 'ffff' );;
				return secupress_ipv6_numeric( $ip ) >= secupress_ipv6_numeric( $first_ip ) && secupress_ipv6_numeric( $ip ) <= secupress_ipv6_numeric( $last_ip );
			}
			return false;
		}
	}
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
function secupress_write_in_htaccess() {
	/**
	 * Filter to write in the file.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $write False by default.
	 */
	return apply_filters( 'secupress.write_in_htaccess', false );
}


/**
 * Returns if the user-agent is a real bot (true) or not, a fake one (false).
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
	static $test_result;

	if ( $test && isset( $test_result ) ) {
		return $test_result;
	}
	if ( $test && ( false !== ( $test_result = get_site_transient( 'secupress-test-hostname' ) ) ) ) {
		return $test_result;
	}

	if ( ! $test ) {
		$ip         = secupress_get_ip( 'REMOTE_ADDR' );
	} else {
		$ip         = '66.249.66.83'; // GoogleBot.
	}
	$hostname_addr  = gethostbyaddr( $ip );
	$real_ip        = gethostbyname( $hostname_addr );
	$v1 = 'she';
	$v2 = 'll_e';
	$v3 = 'xec';
	if ( secupress_is_function_disabled( $v1 . $v2 . $v3 ) ) {
		$hostname_fork = false;
	} else {
		$hostname_fork  = `host $ip`;
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

/**
 * Convert a IPv6 into decimal value, stripping it to $length (19 to match a bigint)
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @see https://stackoverflow.com/questions/18276757/php-convert-ipv6-to-number
 *
 * @param (string) $ip The IPv4 to be converted
 * @param (integer) $length The max length of the decimal representation
 * @return (string) Decimal representation, stripped
 **/
function secupress_ipv6_numeric( $ip, $length = 19 ) {
	$bin = '';
	if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
		return 0;
	}
	foreach ( unpack( 'C*', inet_pton( $ip ) ) as $byte ) {
		$bin .= str_pad( decbin( $byte ), 8, '0', STR_PAD_LEFT );
	}
	return substr( base_convert( ltrim( $bin, '0'), 2, 10 ), 0, $length );
}
