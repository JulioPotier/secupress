<?php
/**
 * Module Name: Block Bad URL Length
 * Description: Block requests containing more than 300 (default) chars in URL.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

$parse_url = explode( '?', $_SERVER['REQUEST_URI'] );
$parse_url = parse_str( end( $parse_url ), $args );

unset( $args['_wp_http_referer'] );

/**
 * Filter the request uri arguments.
 *
 * @since 1.0
 *
 * @param (array) $args The request uri arguments.
 */
$args = apply_filters( 'secupress.plugin.bad-url-length.args', $args );

/**
 * Filter the maximum uri length.
 *
 * @since 1.0
 *
 * @param (int) $length The maximum length. Default is 300.
 */
$length = apply_filters( 'secupress.plugin.bad-url-length.len', 300 );

$url_test = http_build_query( $args );

if ( strlen( $url_test ) > $length ) {
	secupress_block( 'BUL', 414 );
}

unset( $url_test, $args, $parse_url, $length );
