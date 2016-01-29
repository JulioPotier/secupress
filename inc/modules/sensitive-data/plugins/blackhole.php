<?php
/*
Module Name: Blackhole
Description: Catch bots that don't respect your <code>robots.txt</code> rules.
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


/**
 * Add forbidden URI in `robots.txt` file.
 *
 * @since 1.0
 *
 * @param (string) File content.
 *
 * @return (string) File content.
 */
add_filter( 'robots_txt', 'secupress_blackhole_robots_txt' );

function secupress_blackhole_robots_txt( $output ) {
	$dirname = secupress_get_hashed_folder_name( 'blackhole' );

	if ( false !== strpos( $output, "User-agent: *\n" ) ) {
		$output  = str_replace( "User-agent: *\n", "User-agent: *\nDisallow: $dirname\n", $output );
	} else {
		$output .= "\nUser-agent: *\nDisallow: $dirname\n";
	}

	return $output;
}


/**
 * Use a custom template for our trap.
 *
 * @since 1.0
 *
 * @param (string) Template path.
 *
 * @return (string) Template path.
 */
add_filter( 'template_include', 'secupress_blackhole_please_click_me', 1 );

function secupress_blackhole_please_click_me( $template ) {
	$url     = trailingslashit( secupress_get_current_url() );
	$dirname = secupress_get_hashed_folder_name( 'blackhole' );

	if ( substr( $url, - strlen( $dirname ) ) === $dirname ) {
		return dirname( __FILE__ ) . '/inc/php/blackhole/warning-template.php';
	}

	return $template;
}


/**
 * Ban an IP address and die.
 *
 * @since 1.0
 */
add_action( 'admin_post_nopriv_secupress-ban-me-please', 'secupress_blackhole_ban_ip' );

function secupress_blackhole_ban_ip() {
	$IP      = secupress_get_ip();
	$ban_ips = get_site_option( SECUPRESS_BAN_IP );

	if ( ! is_array( $ban_ips ) ) {
		$ban_ips = array();
	}

	$ban_ips[ $IP ] = time() + MONTH_IN_SECONDS; // Now you got 1 month to think about your future, kiddo. In the meantime, go clean your room.

	update_site_option( SECUPRESS_BAN_IP, $ban_ips );

	/* This hook is documented in /inc/functions/admin.php */
	do_action( 'secupress.ip_banned', $IP, $ban_ips );

	if ( apply_filters( 'write_ban_in_htaccess', true ) ) {
		secupress_write_htaccess( 'ban_ip', secupress_get_htaccess_ban_ip() );
	}

	$msg = sprintf( __( 'Your IP address %s has been banned.', 'secupress' ), '<code>' . esc_html( $IP ) . '</code>' );
	secupress_die( $msg );
}
