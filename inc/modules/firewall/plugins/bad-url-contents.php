<?php
/**
 * Module Name: Block Bad URL Contents
 * Description: Block requests containing bad keywords in URL.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'secupress.plugins.loaded', 'secupress_block_bad_url_contents', 0 );
/**
 * Filter the query string to block the request or not
 *
 * @since 1.0
 */
function secupress_block_bad_url_contents() {

	if ( empty( $_SERVER['QUERY_STRING'] ) ) {
		return;
	}

	$bad_url_contents = secupress_get_module_option( 'bbq-url-content_bad-contents-list', '', 'firewall' );

	if ( ! empty( $bad_url_contents ) ) {
		$bad_url_contents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_url_contents, '/' ) );
		$bad_url_contents = trim( $bad_url_contents, '| ' );

		while ( false !== strpos( $bad_url_contents, '||' ) ) {
			$bad_url_contents = str_replace( '||', '|', $bad_url_contents );
		}
	}

	if ( $bad_url_contents && preg_match( '/' . $bad_url_contents . '/i', $_SERVER['QUERY_STRING'] ) ) {
		secupress_block( 'BUC', 503 );
	}
}
