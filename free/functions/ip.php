<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get the IP address of the current user.
 *
 * @since 2.2.3 Security Fix: Only get IP from REMOTE_ADDR
 * @since 1.4.3 Add $priority param
 * @since 1.0
 *
 * @param (string) $priority Contains a key from $keys to be read first.
 * @return (string)
 */
function secupress_get_ip() {
	/**
	 * Filter the IP address.
	 *
	 * @since 1.0
	 *
	 * @param (string) $ip The IP address.
	 */
	return apply_filters( 'secupress.ip.get_ip', isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0' );
}


/**
 * Tell if an IP address is valid.
 *
 * @since 2.2.6 $flag - null by default
 * @since 1.0
 * @author Julio Potier
 *
 * @param (string) $ip An IP address.
 * @param (bool) $range_format If we have to check in ranges format.
 * @param (null|int) $flag Flags from filter_var() or NULL but not 0 !
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
	$ipv6 = array_merge( $ipv6, array_fill( count( $ipv6 ), 8 - count( $ipv6 ), '0/ffff' ) );
	$ipv6 = implode( ':', $ipv6 );
	$temp = explode( '::-', $ipv6 );
	$ipv6 = $temp[0] . str_repeat( ':0/ffff', 7 - substr_count( $temp[0], ':' ) );
	$ipv6 = str_replace( '0/ffff', $mask, $ipv6 );
	return $ipv6;
}

/**
 * Tell if an IP address is whitelisted.
 *
 * @since 2.2.3 0.0.0.0 is not whitelisted anymore
 * @since 1.4.9 $in_range param
 * @since 1.0
 *
 * @param (string) $ip An IP address. If not provided, the current IP by default.
 * @param (bool) $in_range Specify if the whitelist should aso be tested including ranged ips
 *
 * @return (bool).
 */
function secupress_ip_is_whitelisted( $ip = null, $in_range = true ) {
	$ip = $ip ? $ip : secupress_get_ip();

	/**
	 * Filter the possibility for an IP to bypass the function
	 *
	 * @since 2.2.6
	 *
	 * @param (void|bool) null, a bool will cut the answer
	 * @param (string) $ip The IP address.
	 */
	$early_return = apply_filters( 'secupress.ip_is_allowed', null, $ip );
	if ( is_bool( $early_return ) ) {
		return $early_return;
	}

	if ( ! secupress_ip_is_valid( $ip ) ) {
		return false;
	}

	// Some hardcoded IPs that are always whitelisted.
	$whitelist = [
		'::1'  => 1,
		// '0.0.0.0' => 1, // now blacklisted by default
		'127.0.0.1' => 1,
		// WP Rocket.
		'108.162.192.0/18' => 1,
		'162.19.77.41/32' => 1,
		'141.94.3.241/32' => 1,
		'131.0.72.0/22' => 1,
		'198.41.128.0/17' => 1,
		'141.101.64.0/18' => 1,
		'104.24.0.0/14' => 1,
		'15.235.13.219/32' => 1,
		'103.22.200.0/22' => 1,
		'103.31.4.0/22' => 1,
		'162.19.21.173/32' => 1,
		'104.16.0.0/13' => 1,
		'197.234.240.0/22' => 1,
		'190.93.240.0/20' => 1,
		'46.30.214.0/24' => 1,
		'198.244.203.243/32' => 1,
		'135.125.87.118/32' => 1,
		'162.19.80.122/32' => 1,
		'46.30.211.0/24' => 1,
		'148.113.161.163/32' => 1,
		'15.235.85.140/32' => 1,
		'188.114.96.0/20' => 1,
		'148.113.161.164/32' => 1,
		'172.64.0.0/13' => 1,
		'15.235.11.139/32' => 1,
		'198.244.203.19/32' => 1,
		'46.30.212.0/24' => 1,
		'198.244.203.244/32' => 1,
		'135.125.96.137/32' => 1,
		'162.158.0.0/15' => 1,
		'173.245.48.0/20' => 1,
		'51.222.152.20/32' => 1,
		'185.10.8.0/22' => 1,
		'46.30.210.0/24' => 1,
		'57.128.72.100/32' => 1,
		'141.94.3.242/32' => 1,
		'103.21.244.0/22' => 1,
		'51.222.152.27/32' => 1,
		'148.113.162.204/32' => 1,		
		// WP Umbrella
		'212.129.45.77',
		'212.83.142.5',
		'212.83.175.107',
		'2001:41d0:306:1702::/64',
		'2001:BC8:2B7F:801::292/64',
		// https://my.pingdom.com/probes/ipv4
		'13.232.220.164',
		'23.22.2.46',
		'23.83.129.219',
		'23.92.127.2',
		'23.106.37.99',
		'23.111.152.74',
		'23.111.159.174',
		'43.225.198.122',
		'43.229.84.12',
		'46.20.45.18',
		'46.246.122.10',
		'50.2.185.66',
		'50.16.153.186',
		'52.0.204.16',
		'52.24.42.103',
		'52.48.244.35',
		'52.52.34.158',
		'52.52.95.213',
		'52.52.118.192',
		'52.57.132.90',
		'52.59.46.112',
		'52.59.147.246',
		'52.62.12.49',
		'52.63.142.2',
		'52.63.164.147',
		'52.63.167.55',
		'52.67.148.55',
		'52.73.209.122',
		'52.89.43.70',
		'52.194.115.181',
		'52.197.31.124',
		'52.197.224.235',
		'52.198.25.184',
		'52.201.3.199',
		'52.209.34.226',
		'52.209.186.226',
		'52.210.232.124',
		'54.68.48.199',
		'54.70.202.58',
		'54.94.206.111',
		'64.237.49.203',
		'64.237.55.3',
		'66.165.229.130',
		'66.165.233.234',
		'72.46.130.18',
		'72.46.131.10',
		'76.164.234.106',
		'76.164.234.130',
		'82.103.136.16',
		'82.103.139.165',
		'82.103.145.126',
		'85.195.116.134',
		'89.163.146.247',
		'89.163.242.206',
		'94.75.211.73',
		'94.75.211.74',
		'94.247.174.83',
		'96.47.225.18',
		'103.47.211.210',
		'104.129.24.154',
		'104.129.30.18',
		'107.182.234.77',
		'108.181.70.3',
		'148.72.170.233',
		'148.72.171.17',
		'151.106.52.134',
		'162.218.67.34',
		'162.253.128.178',
		'168.1.203.46',
		'169.51.2.18',
		'169.54.70.214',
		'172.241.112.86',
		'173.248.147.18',
		'173.254.206.242',
		'174.34.156.130',
		'175.45.132.20',
		'178.162.206.244',
		'179.50.12.212',
		'184.75.210.90',
		'184.75.210.226',
		'184.75.214.66',
		'184.75.214.98',
		'185.39.146.214',
		'185.39.146.215',
		'185.70.76.23',
		'185.93.3.65',
		'185.136.156.82',
		'185.152.65.167',
		'185.180.12.65',
		'185.246.208.82',
		'190.120.230.7',
		'196.240.207.18',
		'196.244.191.18',
		'196.245.151.42',
		'199.87.228.66',
		'200.58.101.248',
		'201.33.21.5',
		'207.244.80.239',
		'209.58.139.193',
		'209.58.139.194',
		'209.95.50.14',
		'212.78.83.12',
		'212.78.83.16',
		// https://uptimerobot.com/inc/files/ips/IPv4.txt
		'216.144.250.150' => 1,
		'69.162.124.226' => 1,
		'69.162.124.227' => 1,
		'69.162.124.228' => 1,
		'69.162.124.229' => 1,
		'69.162.124.230' => 1,
		'69.162.124.231' => 1,
		'69.162.124.232' => 1,
		'69.162.124.233' => 1,
		'69.162.124.234' => 1,
		'69.162.124.235' => 1,
		'69.162.124.236' => 1,
		'69.162.124.237' => 1,
		'63.143.42.242' => 1,
		'63.143.42.243' => 1,
		'63.143.42.244' => 1,
		'63.143.42.245' => 1,
		'63.143.42.246' => 1,
		'63.143.42.247' => 1,
		'63.143.42.248' => 1,
		'63.143.42.249' => 1,
		'63.143.42.250' => 1,
		'63.143.42.251' => 1,
		'63.143.42.252' => 1,
		'63.143.42.253' => 1,
		'216.245.221.82' => 1,
		'216.245.221.83' => 1,
		'216.245.221.84' => 1,
		'216.245.221.85' => 1,
		'216.245.221.86' => 1,
		'216.245.221.87' => 1,
		'216.245.221.88' => 1,
		'216.245.221.89' => 1,
		'216.245.221.90' => 1,
		'216.245.221.91' => 1,
		'216.245.221.92' => 1,
		'216.245.221.93' => 1,
		'46.137.190.132' => 1,
		'122.248.234.23' => 1,
		'188.226.183.141' => 1,
		'178.62.52.237' => 1,
		'54.79.28.129' => 1,
		'54.94.142.218' => 1,
		'104.131.107.63' => 1,
		'54.67.10.127' => 1,
		'54.64.67.106' => 1,
		'159.203.30.41' => 1,
		'46.101.250.135' => 1,
		'18.221.56.27' => 1,
		'52.60.129.180' => 1,
		'159.89.8.111' => 1,
		'146.185.143.14' => 1,
		'139.59.173.249' => 1,
		'165.227.83.148' => 1,
		'128.199.195.156' => 1,
		'138.197.150.151' => 1,
		'34.233.66.117' => 1,
		// https://app.statuscake.com/Workfloor/Locations.php?format=txt
		'216.144.250.150',
		'69.162.124.226',
		'69.162.124.227',
		'69.162.124.228',
		'69.162.124.229',
		'69.162.124.230',
		'69.162.124.231',
		'69.162.124.232',
		'69.162.124.233',
		'69.162.124.234',
		'69.162.124.235',
		'69.162.124.236',
		'69.162.124.237',
		'69.162.124.238',
		'63.143.42.242',
		'63.143.42.243',
		'63.143.42.244',
		'63.143.42.245',
		'63.143.42.246',
		'63.143.42.247',
		'63.143.42.248',
		'63.143.42.249',
		'63.143.42.250',
		'63.143.42.251',
		'63.143.42.252',
		'63.143.42.253',
		'216.245.221.82',
		'216.245.221.83',
		'216.245.221.84',
		'216.245.221.85',
		'216.245.221.86',
		'216.245.221.87',
		'216.245.221.88',
		'216.245.221.89',
		'216.245.221.90',
		'216.245.221.91',
		'216.245.221.92',
		'216.245.221.93',
		'208.115.199.18',
		'208.115.199.19',
		'208.115.199.20',
		'208.115.199.21',
		'208.115.199.22',
		'208.115.199.23',
		'208.115.199.24',
		'208.115.199.25',
		'208.115.199.26',
		'208.115.199.27',
		'208.115.199.28',
		'208.115.199.29',
		'208.115.199.30',
		'216.144.248.18',
		'216.144.248.19',
		'216.144.248.20',
		'216.144.248.21',
		'216.144.248.22',
		'216.144.248.23',
		'216.144.248.24',
		'216.144.248.25',
		'216.144.248.26',
		'216.144.248.27',
		'216.144.248.28',
		'216.144.248.29',
		'216.144.248.30',
		'46.137.190.132',
		'122.248.234.23',
		'167.99.209.234',
		'178.62.52.237',
		'54.79.28.129',
		'54.94.142.218',
		'104.131.107.63',
		'54.67.10.127',
		'54.64.67.106',
		'159.203.30.41',
		'46.101.250.135',
		'18.221.56.27',
		'52.60.129.180',
		'159.89.8.111',
		'146.185.143.14',
		'139.59.173.249',
		'165.227.83.148',
		'128.199.195.156',
		'138.197.150.151',
		'34.233.66.117',
		'52.70.84.165',
		'54.225.82.45',
		'54.224.73.211',
		'3.79.92.117',
		'3.21.136.87',
		'35.170.215.196',
		'35.153.243.148',
		'18.116.158.121',
		'18.223.50.16',
		'54.241.175.147',
		'3.212.128.62',
		'52.22.236.30',
		'54.167.223.174',
		'3.12.251.153',
		'52.15.147.27',
		'18.116.205.62',
		'3.20.63.178',
		'13.56.33.4',
		'52.8.208.143',
		'34.198.201.66',
		'35.84.118.171',
		'44.227.38.253',
		'35.166.228.98',
		'99.80.173.191',
		'99.80.1.74',
		'3.111.88.158',
		'13.127.188.124',
		'18.180.208.214',
		'54.249.170.27',
		'3.105.190.221',
		'3.105.133.239',
		'78.47.98.55',
		'157.90.155.240',
		'49.13.24.81',
		'168.119.96.239',
		'157.90.156.63',
		'88.99.80.227',
		'49.13.134.145',
		'49.13.130.29',
		'168.119.53.160',
		'142.132.180.39',
		'49.13.164.148',
		'128.140.106.114',
		'78.47.173.76',
		'159.69.158.189',
		'128.140.41.193',
		'167.235.143.113',
		'49.13.167.123',
		'78.46.215.1',
		'78.46.190.63',
		'168.119.123.75',
		'135.181.154.9',
		'37.27.87.149',
		'37.27.34.49',
		'37.27.82.220',
		'65.109.129.165',
		'37.27.28.153',
		'37.27.29.68',
		'37.27.30.213',
		'65.109.142.78',
		'65.109.8.202',
		'5.161.75.7',
		'5.161.61.238',
		'5.78.87.38',
		'5.78.118.142',
		// https://updown.io/about
		'45.32.74.41' => 1,
		'104.238.136.194' => 1,
		'192.99.37.47',
		'198.27.83.55' => 1,
		'91.121.222.175' => 1,
		'104.238.159.87' => 1,
		'135.181.102.135',
		'45.32.107.181' => 1,
		'45.76.104.117' => 1,
		'45.63.29.207' => 1,
	];

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
 * @since 2.2.3 0.0.0.0 is now blacklisted
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
	$blacklist            = get_site_option( SECUPRESS_BAN_IP );
	$blacklist            = array_flip( array_keys( $blacklist ) );
	$blacklist['0.0.0.0'] = 1;
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
 * @since 2.2.3 Use "continue" instad of "return" too soon.
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

				if ( ip2long( $ip ) >= ip2long( $first_ip ) && ip2long( $ip ) <= ip2long( $last_ip ) ) {
					return true;
				}
				continue;
			}
			if ( strpos( $_ips, '/' ) ) {
				list( $first_ip, $mask ) = explode( '/', $_ips );
				if ( $mask === '0' ) {
					return true;
				}
				if ( $mask < 0 || $mask > 32 ) {
					continue;
				}
				if ( 0 === substr_compare( sprintf( '%032b', ip2long( $ip ) ), sprintf( '%032b', ip2long( $first_ip ) ), 0, $mask ) ) {
					return true;
				}
				continue;
			}
			if ( strpos( $_ips, '*' ) ) {
				$mask     = str_replace( '*', '', $_ips );
				$mask     = explode( '.', $mask );
				$mask     = array_filter( $mask );
				$mask     = $mask + array_fill( count( $mask ), 4 - count( $mask ), '0/255' );
				$mask     = implode( '.', $mask );
				$first_ip = str_replace( '0/255', '0', $mask );
				$last_ip  = str_replace( '0/255', '255', $mask );

				if ( ip2long( $ip ) >= ip2long( $first_ip ) && ip2long( $ip ) <= ip2long( $last_ip ) ) {
					return true;
				}
				continue;
			}
		} elseif ( secupress_ip_is_valid( $ip, true, FILTER_FLAG_IPV6 ) && secupress_ip_is_valid( $_ips, true, FILTER_FLAG_IPV6 ) ) {
			if ( 0 === strcmp( $ip, $_ips ) ) {
				return true;
			}
			if ( strpos( $_ips, '::-' ) ) {
				$temp     = explode( '::-', $_ips );
				$first_ip = $temp[0] . str_repeat( ':0', 7 - substr_count( $temp[0], ':' ) );
				$last_ip  = $temp[1];

				if ( secupress_ipv6_numeric( $ip ) >= secupress_ipv6_numeric( $first_ip ) && secupress_ipv6_numeric( $ip ) <= secupress_ipv6_numeric( $last_ip ) ) {
					return true;
				}
				continue;
			}
			if ( strpos( $_ips, '/' ) ) {
				list( $first_ip, $mask ) = explode( '/', $_ips, 2 );
				if ($mask < 1 || $mask > 128) {
					continue;
				}
				$bytesAddr = unpack( 'n*', @inet_pton( $first_ip ) );
				$bytesTest = unpack( 'n*', @inet_pton( $ip ) );
				if ( ! $bytesAddr || ! $bytesTest ) {
					continue;
				}
				for ( $i = 1, $ceil = ceil( $mask / 16 ); $i <= $ceil; ++$i ) {
					$left = $mask - 16 * ( $i - 1 );
					$left = ( $left <= 16 ) ? $left : 16;
					$mask = ~ ( 0xffff >> $left ) & 0xffff;
					if ( ( $bytesAddr[$i] & $mask ) != ( $bytesTest[$i] & $mask ) ) {
						continue;
					}
					return true;
				}
				continue;
			}
			if ( strpos( $_ips, '*' ) ) {
				$_ips     = str_replace( '*', '', $_ips );
				$first_ip = secupress_get_full_ipv6( $_ips, '0' );
				$last_ip  = secupress_get_full_ipv6( $_ips, 'ffff' );
				if ( secupress_ipv6_numeric( $ip ) >= secupress_ipv6_numeric( $first_ip ) && secupress_ipv6_numeric( $ip ) <= secupress_ipv6_numeric( $last_ip ) ) {
					return true;
				}
				continue;
			}
		}
	}
	return false;
}

/**
 * Ban an IP address if not whitelisted.
 * Will add the IP to the list of banned IPs. Will maybe write the IPs in the `.htaccess` file. Will maybe forbid access to the user by displaying a message.
 *
 * @since 1.0
 *
 * @param (int)    $time_ban Ban duration in minutes. Only used in the message.
 * @param (string) $ip       The IP to ban.
 * @param (array)   $die      True to forbid access to the user by displaying a message.
 */
function secupress_ban_ip( $time_ban = 5, $ip = null, $args = [] ) {
	$ip = $ip ? $ip : secupress_get_ip();

	if ( secupress_ip_is_whitelisted( $ip ) ) {
		return;
	}

	$time_ban = (int) $time_ban > 0 ? (int) $time_ban : 5;
	$ban_ips  = get_site_option( SECUPRESS_BAN_IP );
	$ban_ips  = is_array( $ban_ips ) ? $ban_ips : array();
	if ( is_bool( $args ) ) {
		$args['die'] = true;
	}
	$die             = isset( $args['die'] ) && $args['die'];
	$attack_type     = isset( $args['attack_type'] ) ? $args['attack_type'] : 'ban_ip';

	$ban_ips[ $ip ]  = time();

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
		), [ 'force_die' => true, 'context' => 'ban_ip', 'attack_type' => $attack_type ] );
	}
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
		try {
			$hostname_fork  = `host $ip`;
		} catch (Exception $e) {
			$hostname_fork = false;
		}
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
 * @source https://stackoverflow.com/questions/18276757/php-convert-ipv6-to-number
 *
 * @param (string)  $ip     The IPv6 to be converted
 * @param (integer) $length The max length of the decimal representation, "19" by default
 * @return (string) Decimal representation, stripped
 **/
function secupress_ipv6_numeric( $ip, $length = 19 ) {
	$bin = '';
	if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
		return '0';
	}
	foreach ( unpack( 'C*', inet_pton( $ip ) ) as $byte ) {
		$bin .= str_pad( decbin( $byte ), 8, '0', STR_PAD_LEFT );
	}
	return substr( base_convert( ltrim( $bin, '0'), 2, 10 ), 0, $length );
}

/**
 * Get a headers array from the licence data to build the Authorization
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (string) $consumer_email
 * @param (string) $consumer_key
 * 
 * @return (array) Contains HTTP Basic Auth
 **/
function secupress_get_basic_auth_headers( $consumer_email = '', $consumer_key = '' ) {
	$consumer_email = $consumer_email ?: secupress_get_consumer_email();
	$consumer_key   = $consumer_key   ?: secupress_get_consumer_key();

	return [ 'Authorization' => 'Basic ' . base64_encode( $consumer_email . ':' . $consumer_key ) ];
}