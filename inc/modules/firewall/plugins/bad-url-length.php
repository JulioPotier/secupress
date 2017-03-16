<?php
/**
 * Module Name: Block Bad URL Length
 * Description: Block requests containing more than 300 (default) chars in URL.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

define( 'SECUPRESS_BBUL_HEADER_NAME', 'X-SECUPRESS-BBUL-NONCE' );


/**
 * Block the current request if the requested URL is too long.
 *
 * @since 1.2.3
 * @author Julio Potier
 */
function secupress_block_too_long_url() {
	$parse_url = explode( '?', $_SERVER['REQUEST_URI'], 2 );
	$parse_url = end( $parse_url );
	wp_parse_str( $parse_url, $args );

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

	if ( mb_strlen( $url_test ) <= $length ) {
		// The URL is not too long.
		return;
	}

	if ( ! secupress_is_scan_request() ) {
		// Search for our nonce.
		$header_name = 'HTTP_' . str_replace( '-', '_', SECUPRESS_BBUL_HEADER_NAME );

		foreach ( $_SERVER as $key => $val ) {
			if ( strtoupper( $key ) !== $header_name ) {
				// Not the header we want.
				continue;
			}
			// We found our header.
			if ( wp_verify_nonce( $val, 'secupress_block_too_long_url' ) ) {
				// The nonce is fine, bail out.
				return;
			}
			// The nonce is not OK (and no need to continue our loop).
			break;
		}
	}

	// Block.
	secupress_block( 'BUL', 414 );
}

secupress_block_too_long_url();


add_filter( 'http_request_args', 'secupress_bbul_add_nonce_header', 10, 2 );
/**
 * For a local request, add a nonce in a header.
 *
 * @since 1.2.3
 * @author Grégory Viguier
 *
 * @param (array)  $r   The request parameters.
 * @param (string) $url The request URL.
 *
 * @return (array)
 */
function secupress_bbul_add_nonce_header( $r, $url ) {
	static $local_url;

	if ( ! isset( $local_url ) ) {
		$local_url = trailingslashit( set_url_scheme( home_url() ) );
	}

	$url = trailingslashit( set_url_scheme( $url ) );

	if ( strpos( $url, $local_url ) === 0 ) {
		// It's a local request.
		$r['headers'][ SECUPRESS_BBUL_HEADER_NAME ] = wp_create_nonce( 'secupress_block_too_long_url' );
	}

	return $r;
}
