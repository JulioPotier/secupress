<?php
/**
 * Module Name: Block Bad URL Contents
 * Description: Block requests containing bad keywords in URL.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0.1
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


add_filter( 'secupress.options.load_plugins_network_options', 'secupress_block_bad_url_contents_autoload_options' );
/**
 * Add the option(s) we use in this plugin to be autoloaded.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (array) $option_names An array of network option names.
 *
 * @return (array)
 */
function secupress_block_bad_url_contents_autoload_options( $option_names ) {
	$option_names[] = 'secupress_firewall_settings';
	return $option_names;
}
