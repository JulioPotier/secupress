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
	return apply_filters('secupress.ip.get_ip', isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0' );
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
function secupress_ip_is_valid( $ip, $range_format = false , $flag = 0 ) {
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

	if ( ! secupress_ip_is_valid( $ip ) ) {
		return false;
	}

	// Some hardcoded IPs that are always whitelisted.
	$whitelist = [
		'::1'  => 1,
		// '0.0.0.0' => 1, // now blacklisted by default
		'127.0.0.1' => 1,
		// WP Rocket.
		'37.187.85.82' => 1,
		'37.187.58.236' => 1,
		'167.114.234.234' => 1,
		// https://my.pingdom.com/probes/ipv4
		'5.172.196.188' => 1,
		'13.232.220.164' => 1,
		'23.22.2.46' => 1,
		'23.83.129.219' => 1,
		'23.111.152.74' => 1,
		'23.111.159.174' => 1,
		'27.122.14.7' => 1,
		'37.252.231.50' => 1,
		'43.225.198.122' => 1,
		'43.229.84.12' => 1,
		'46.20.45.18' => 1,
		'46.165.195.139' => 1,
		'46.246.122.10' => 1,
		'50.16.153.186' => 1,
		'50.23.28.35' => 1,
		'52.0.204.16' => 1,
		'52.24.42.103' => 1,
		'52.48.244.35' => 1,
		'52.52.34.158' => 1,
		'52.52.95.213' => 1,
		'52.52.118.192' => 1,
		'52.57.132.90' => 1,
		'52.59.46.112' => 1,
		'52.59.147.246' => 1,
		'52.62.12.49' => 1,
		'52.63.142.2' => 1,
		'52.63.164.147' => 1,
		'52.63.167.55' => 1,
		'52.67.148.55' => 1,
		'52.73.209.122' => 1,
		'52.89.43.70' => 1,
		'52.194.115.181' => 1,
		'52.197.31.124' => 1,
		'52.197.224.235' => 1,
		'52.198.25.184' => 1,
		'52.201.3.199' => 1,
		'52.209.34.226' => 1,
		'52.209.186.226' => 1,
		'52.210.232.124' => 1,
		'54.68.48.199' => 1,
		'54.70.202.58' => 1,
		'54.94.206.111' => 1,
		'64.237.49.203' => 1,
		'64.237.55.3' => 1,
		'66.165.229.130' => 1,
		'66.165.233.234' => 1,
		'72.46.130.18' => 1,
		'72.46.130.44' => 1,
		'76.72.167.90' => 1,
		'76.72.167.154' => 1,
		'76.72.172.208' => 1,
		'76.164.234.106' => 1,
		'76.164.234.170' => 1,
		'81.17.62.205' => 1,
		'82.103.136.16' => 1,
		'82.103.139.165' => 1,
		'82.103.145.126' => 1,
		'83.170.113.210' => 1,
		'85.93.93.124' => 1,
		'85.93.93.133' => 1,
		'85.195.116.134' => 1,
		'89.163.146.247' => 1,
		'89.163.242.206' => 1,
		'94.75.211.73' => 1,
		'94.75.211.74' => 1,
		'94.247.174.83' => 1,
		'95.141.32.46' => 1,
		'95.211.198.87' => 1,
		'96.47.225.18' => 1,
		'103.47.211.210' => 1,
		'104.129.24.154' => 1,
		'104.129.30.18' => 1,
		'109.123.101.103' => 1,
		'138.219.43.186' => 1,
		'148.72.170.233' => 1,
		'148.72.171.17' => 1,
		'151.106.52.134' => 1,
		'162.218.67.34' => 1,
		'168.1.92.58' => 1,
		'169.51.2.22' => 1,
		'169.56.174.147' => 1,
		'172.241.112.86' => 1,
		'173.248.147.18' => 1,
		'173.254.206.242' => 1,
		'174.34.156.130' => 1,
		'175.45.132.20' => 1,
		'178.255.152.2' => 1,
		'178.255.153.2' => 1,
		'178.255.155.2' => 1,
		'179.50.12.212' => 1,
		'184.75.208.210' => 1,
		'184.75.209.18' => 1,
		'184.75.210.90' => 1,
		'184.75.210.226' => 1,
		'184.75.214.66' => 1,
		'185.39.146.214' => 1,
		'185.39.146.215' => 1,
		'185.70.76.23' => 1,
		'185.93.3.92' => 1,
		'185.136.156.82' => 1,
		'185.152.65.167' => 1,
		'185.180.12.65' => 1,
		'185.246.208.82' => 1,
		'188.172.252.34' => 1,
		'199.87.228.66' => 1,
		'201.33.21.5' => 1,
		'207.244.80.239' => 1,
		'209.58.139.193' => 1,
		'209.58.139.194' => 1,
		'209.126.117.87' => 1,
		'209.126.120.29' => 1,
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
		'128.199.222.65' => 1,
		'188.166.158.224' => 1,
		'139.59.152.248' => 1,
		'199.167.128.80' => 1,
		'188.226.135.210' => 1,
		'45.32.69.14' => 1,
		'37.235.53.240' => 1,
		'45.32.195.225' => 1,
		'192.241.221.11' => 1,
		'108.61.162.214' => 1,
		'37.235.48.42' => 1,
		'158.255.208.76' => 1,
		'45.76.123.211' => 1,
		'178.209.51.248' => 1,
		'103.14.141.200' => 1,
		'213.183.56.85' => 1,
		'194.187.248.52' => 1,
		'91.236.116.138' => 1,
		'37.235.55.35' => 1,
		'194.187.248.53' => 1,
		'45.63.104.11' => 1,
		'45.32.151.21' => 1,
		'107.170.227.23' => 1,
		'107.170.227.24' => 1,
		'188.226.169.228' => 1,
		'188.226.185.106' => 1,
		'188.226.186.199' => 1,
		'45.32.202.57' => 1,
		'188.226.171.58' => 1,
		'108.61.119.153' => 1,
		'188.226.158.160' => 1,
		'45.32.139.194' => 1,
		'108.61.252.147' => 1,
		'23.227.191.111' => 1,
		'144.168.43.155' => 1,
		'178.62.78.199' => 1,
		'209.222.30.242' => 1,
		'46.101.74.251' => 1,
		'108.61.212.141' => 1,
		'178.62.65.162' => 1,
		'178.62.109.7' => 1,
		'188.226.247.184' => 1,
		'188.226.139.158' => 1,
		'188.226.184.152' => 1,
		'178.62.106.84' => 1,
		'104.131.248.65' => 1,
		'104.131.248.78' => 1,
		'46.101.61.83' => 1,
		'104.131.247.151' => 1,
		'178.62.86.69' => 1,
		'107.170.197.248' => 1,
		'107.170.219.46' => 1,
		'188.226.203.84' => 1,
		'178.62.41.44' => 1,
		'178.62.41.49' => 1,
		'178.62.41.52' => 1,
		'162.243.71.56' => 1,
		'178.62.40.233' => 1,
		'162.243.247.163' => 1,
		'107.170.53.191' => 1,
		'178.62.80.93' => 1,
		'178.62.71.227' => 1,
		'178.73.210.99' => 1,
		'181.41.214.137' => 1,
		'154.127.60.59' => 1,
		'194.71.130.16' => 1,
		'46.101.240.208' => 1,
		'46.101.238.182' => 1,
		'46.101.238.189' => 1,
		'46.101.27.186' => 1,
		'178.62.104.137' => 1,
		'193.182.144.211' => 1,
		'159.203.31.18' => 1,
		'193.234.225.128' => 1,
		'138.204.171.136' => 1,
		'213.183.56.79' => 1,
		'154.127.60.23' => 1,
		'188.166.253.148' => 1,
		'37.157.246.146' => 1,
		'46.101.110.43' => 1,
		'46.101.110.45' => 1,
		'178.62.101.57' => 1,
		'46.101.0.24' => 1,
		'46.101.20.96' => 1,
		'46.101.110.32' => 1,
		'37.235.52.25' => 1,
		'192.71.249.248' => 1,
		'192.71.245.103' => 1,
		'37.235.53.156' => 1,
		'37.235.48.146' => 1,
		'91.239.125.60' => 1,
		'139.59.15.79' => 1,
		'185.241.7.23' => 1,
		'45.63.121.159' => 1,
		'45.32.145.79' => 1,
		'181.41.201.117' => 1,
		'151.236.10.238' => 1,
		'199.247.12.100' => 1,
		'213.183.54.66' => 1,
		'185.135.81.201' => 1,
		'138.68.24.60' => 1,
		'107.191.47.131' => 1,
		'138.68.24.115' => 1,
		'138.68.24.136' => 1,
		'138.68.24.207' => 1,
		'138.197.140.243' => 1,
		'138.197.130.232' => 1,
		'138.197.130.235' => 1,
		'139.59.155.26' => 1,
		'138.68.80.173' => 1,
		'139.59.190.241' => 1,
		'138.68.80.10' => 1,
		'139.59.29.167' => 1,
		'45.63.88.213' => 1,
		'45.63.86.120' => 1,
		'45.32.128.80' => 1,
		'104.156.229.24' => 1,
		'45.32.212.56' => 1,
		'104.156.255.184' => 1,
		'108.61.215.179' => 1,
		'45.32.166.195' => 1,
		'45.32.160.172' => 1,
		'45.32.171.24' => 1,
		'107.191.57.237' => 1,
		'45.63.26.78' => 1,
		'45.76.192.50' => 1,
		'45.32.36.158' => 1,
		'139.59.26.85' => 1,
		'139.59.22.109' => 1,
		'104.238.164.105' => 1,
		'45.63.76.68' => 1,
		'45.63.78.84' => 1,
		'45.32.195.186' => 1,
		'45.76.3.112' => 1,
		'45.76.1.44' => 1,
		'45.32.7.22' => 1,
		'159.203.186.225' => 1,
		'159.203.182.22' => 1,
		'159.203.182.60' => 1,
		'45.63.51.63' => 1,
		'45.63.61.213' => 1,
		'108.61.205.201' => 1,
		'45.32.192.198' => 1,
		'45.32.195.93' => 1,
		'149.28.79.140' => 1,
		'45.63.97.4' => 1,
		'104.238.185.175' => 1,
		'104.238.185.46' => 1,
		'104.238.186.209' => 1,
		'45.76.128.250' => 1,
		'104.238.171.176' => 1,
		'206.189.49.237' => 1,
		'104.238.187.61' => 1,
		'104.238.174.234' => 1,
		'108.61.196.37' => 1,
		'108.61.197.147' => 1,
		'45.76.134.164' => 1,
		'45.76.135.253' => 1,
		'108.61.173.0' => 1,
		'45.63.96.68' => 1,
		'45.76.134.85' => 1,
		'45.32.183.128' => 1,
		'45.76.130.43' => 1,
		'45.76.129.212' => 1,
		'45.76.134.198' => 1,
		'45.76.134.237' => 1,
		'45.76.135.14' => 1,
		'103.14.141.207' => 1,
		'45.32.193.13' => 1,
		'45.76.44.221' => 1,
		'140.82.52.199' => 1,
		'199.247.9.63' => 1,
		'140.82.52.51' => 1,
		'45.76.23.8' => 1,
		'104.238.164.51' => 1,
		'108.61.229.252' => 1,
		'37.235.49.12' => 1,
		'217.78.0.171' => 1,
		'185.134.28.28' => 1,
		'138.68.77.156' => 1,
		'169.239.183.200' => 1,
		'217.78.1.71' => 1,
		'181.215.238.173' => 1,
		// https://updown.io/about
		'45.32.74.41' => 1,
		'104.238.136.194' => 1,
		'198.27.83.55' => 1,
		'91.121.222.175' => 1,
		'104.238.159.87' => 1,
		'45.32.107.181' => 1,
		'45.76.104.117' => 1,
		'45.63.29.207' => 1,
		// https://www.monitis.com/support/tools/our-ips
		'217.146.28.82' => 1,
		'104.200.152.54' => 1,
		'131.100.0.34' => 1,
		'209.95.50.41' => 1,
		'162.220.220.189' => 1,
		'188.172.216.18' => 1,
		'188.172.212.59' => 1,
		'206.190.152.146' => 1,
		'104.200.159.114' => 1,
		'104.200.159.194' => 1,
		'37.252.245.68' => 1,
		'37.252.249.70' => 1,
		'217.146.12.66' => 1,
		'37.252.244.114' => 1,
		'217.146.9.53' => 1,
		'185.37.151.37' => 1,
		'139.220.243.66' => 1,
		'37.252.229.123' => 1,
		'185.80.220.19' => 1,
		'188.172.192.34' => 1,
		'217.146.22.202' => 1,
		'217.146.6.34' => 1,
		'46.23.67.107' => 1,
		'37.252.230.78' => 1,
		'217.146.1.34' => 1,
		'178.255.155.14' => 1,
		'37.252.254.74' => 1,
		'37.252.227.118' => 1,
		'37.252.225.18' => 1,
		'217.146.31.42' => 1,
		'37.252.233.46' => 1,
		'217.146.13.66' => 1,
		'178.255.153.180' => 1,
		'188.172.217.140' => 1,
		'37.252.240.124' => 1,
		'217.146.28.82' => 1,
		'217.146.28.83' => 1,
		'162.220.221.146' => 1,
		'162.220.221.146' => 1,
		'162.220.221.146' => 1,
		'162.220.221.146' => 1,
		'162.220.221.50' => 1,
		'162.220.221.54' => 1,
		'162.220.221.147' => 1,
		'162.220.221.149' => 1,
		'162.220.221.150' => 1,
		'188.172.214.3' => 1,
		'188.172.214.4' => 1,
		'131.100.0.34' => 1,
		'131.100.0.35' => 1,
		'188.172.212.59' => 1,
		'188.172.212.60' => 1,
		'107.182.239.183' => 1,
		'206.190.152.146' => 1,
		'107.182.238.244' => 1,
		'107.182.234.74' => 1,
		'37.252.238.107' => 1,
		'37.252.238.109' => 1,
		'37.252.238.108' => 1,
		'188.172.244.34' => 1,
		'104.200.159.158' => 1,
		'192.111.140.182' => 1,
		'192.111.140.166' => 1,
		'192.111.140.186' => 1,
		'192.111.140.190' => 1,
		'104.200.159.162' => 1,
		'104.200.159.154' => 1,
		'107.152.102.34' => 1,
		'104.200.159.170' => 1,
		'104.200.159.130' => 1,
		'104.200.159.58' => 1,
		'104.200.159.182' => 1,
		'188.172.212.58' => 1,
		'162.220.220.212' => 1,
		'162.220.220.212' => 1,
		'162.220.220.189' => 1,
		'162.220.220.188' => 1,
		'162.220.220.38' => 1,
		'162.220.220.190' => 1,
		'173.244.217.193' => 1,
		'162.220.220.187' => 1,
		'162.220.220.213' => 1,
		'162.220.220.214' => 1,
		'162.220.220.186' => 1,
		'173.244.200.133' => 1,
		'107.182.226.89' => 1,
		'37.252.245.68' => 1,
		'37.252.245.69' => 1,
		'37.252.249.70' => 1,
		'37.252.249.226' => 1,
		'37.252.249.227' => 1,
		'217.146.12.66' => 1,
		'217.146.12.67' => 1,
		'217.146.12.68' => 1,
		'37.252.244.114' => 1,
		'217.146.9.53' => 1,
		'217.146.9.54' => 1,
		'217.146.9.52' => 1,
		'217.146.9.51' => 1,
		'185.37.151.37' => 1,
		'37.252.229.146' => 1,
		'161.202.72.141' => 1,
		'161.202.144.199' => 1,
		'185.80.220.20' => 1,
		'185.80.220.97' => 1,
		'185.80.221.30' => 1,
		'188.172.192.36' => 1,
		'188.172.192.35' => 1,
		'217.146.6.34' => 1,
		'34.251.25.44' => 1,
		'146.185.26.44' => 1,
		'146.185.23.52' => 1,
		'146.185.23.52' => 1,
		'88.202.186.34' => 1,
		'91.109.247.218' => 1,
		'146.185.16.30' => 1,
		'91.109.247.220' => 1,
		'146.185.23.52' => 1,
		'176.67.175.132' => 1,
		'88.202.231.68' => 1,
		'31.24.228.203' => 1,
		'185.61.124.171' => 1,
		'185.61.124.143' => 1,
		'217.146.1.52' => 1,
		'217.146.1.53' => 1,
		'159.122.133.246' => 1,
		'159.122.133.242' => 1,
		'188.172.218.27' => 1,
		'188.172.218.28' => 1,
		'37.252.254.74' => 1,
		'37.252.227.74' => 1,
		'217.146.30.62' => 1,
		'217.146.30.83' => 1,
		'37.252.227.98' => 1,
		'37.252.227.114' => 1,
		'217.146.30.60' => 1,
		'217.146.30.84' => 1,
		'217.146.30.82' => 1,
		'217.146.30.86' => 1,
		'37.252.227.106' => 1,
		'37.252.227.107' => 1,
		'37.252.227.108' => 1,
		'37.252.225.18' => 1,
		'37.252.225.58' => 1,
		'37.252.225.60' => 1,
		'37.252.225.61' => 1,
		'37.252.225.62' => 1,
		'217.146.31.42' => 1,
		'217.146.31.43' => 1,
		'37.252.233.46' => 1,
		'37.252.233.34' => 1,
		'37.252.233.35' => 1,
		'37.252.233.36' => 1,
		'178.255.153.180' => 1,
		'178.255.153.181' => 1,
		'178.255.153.182' => 1,
		'188.172.235.36' => 1,
		'188.172.217.140' => 1,
		'188.172.217.141' => 1,
		'37.252.240.124' => 1,
		'37.252.240.26' => 1,
		'37.252.240.38' => 1,
		'37.252.240.125' => 1,
		'37.252.238.194' => 1,
		'217.146.22.102' => 1,
		'37.252.229.125' => 1,
		'107.182.231.77' => 1,
		'37.252.238.110' => 1,
		'217.146.22.101' => 1,
		'37.252.229.124' => 1,
		'107.182.231.76' => 1,
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
		), array( 'force_die' => true, 'context' => 'ban_ip' ) );
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
 * @see https://stackoverflow.com/questions/18276757/php-convert-ipv6-to-number
 *
 * @param (string)  $ip     The IPv6 to be converted
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
