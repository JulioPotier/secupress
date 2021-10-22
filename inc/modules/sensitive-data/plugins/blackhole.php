<?php
/**
 * Module Name: Blackhole
 * Description: Catch bots that don't respect your <code>robots.txt</code> rules.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


add_filter( 'robots_txt', 'secupress_blackhole_robots_txt' );
/**
 * Add forbidden URI in `robots.txt` file.
 *
 * @since 1.0
 *
 * @param (string) $output File content.
 *
 * @return (string) File content.
 */
function secupress_blackhole_robots_txt( $output ) {
	if ( is_user_logged_in() || secupress_blackhole_is_whitelisted() ) {
		return $output;
	}

	$dirname = secupress_get_hashed_folder_name( 'blackhole' );

	if ( false !== strpos( $output, "User-agent: *\n" ) ) {
		$output  = str_replace( "User-agent: *\n", "User-agent: *\nDisallow: $dirname\n", $output );
	} else {
		$output .= "\nUser-agent: *\nDisallow: $dirname\n";
	}

	return $output;
}


add_filter( 'template_include', 'secupress_blackhole_please_click_me', 1 );
/**
 * Use a custom template for our trap.
 *
 * @since 1.0
 *
 * @param (string) $template Template path.
 *
 * @return (string) Template path.
 */
function secupress_blackhole_please_click_me( $template ) {
	if ( is_user_logged_in() || secupress_blackhole_is_whitelisted() ) {
		return $template;
	}

	$url     = trailingslashit( secupress_get_current_url() );
	$dirname = secupress_get_hashed_folder_name( 'blackhole' );

	if ( substr( $url, - strlen( $dirname ) ) === $dirname ) {
		return dirname( __FILE__ ) . '/inc/php/blackhole/warning-template.php';
	}

	return $template;
}


add_action( 'admin_post_nopriv_secupress-ban-me-please', 'secupress_blackhole_ban_ip' );
/**
 * Ban an IP address and die.
 *
 * @since 2.0 use REMOTE_ADDR + do not print anything
 * @author Julio Potier
 * @since 1.0
 */
function secupress_blackhole_ban_ip() {
	if ( secupress_blackhole_is_whitelisted() ) {
		return;
	}

	$ip      = secupress_get_ip( 'REMOTE_ADDR' );
	$ban_ips = get_site_option( SECUPRESS_BAN_IP );

	if ( ! is_array( $ban_ips ) ) {
		$ban_ips = array();
	}

	$ban_ips[ $ip ] = time() + MONTH_IN_SECONDS;

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ban.ip_banned', $ip, $ban_ips );

	die();
}


/**
 * Tell if the current user is whitelisted.
 *
 * @since 1.0
 *
 * @return (bool) True if whitelisted, false otherwize.
 */
function secupress_blackhole_is_whitelisted() {
	$ip = secupress_get_ip();
	$ua = ! empty( $_SERVER['HTTP_USER_AGENT'] ) ? esc_html( $_SERVER['HTTP_USER_AGENT'] ) : '';

	// The IP address may be whitelisted.
	if ( secupress_ip_is_whitelisted( $ip ) ) {
		return true;
	}

	/**
	 * Filter the "whitelist".
	 *
	 * @since 1.0
	 *
	 * @param (bool)       True if whitelisted, false otherwize.
	 * @param (string) $ip The user's IP.
	 * @param (string) $ua The user's User-Agent.
	 */
	return apply_filters( 'secupress.plugin.blackhole.is_allowed', false, $ip, $ua );
}
