<?php
/*
Module Name: Block Bad URLs Contents
Description: Block requests containing bad keywords in URL
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

add_action( 'secupress_plugins_loaded', 'secupress_block_bad_url_contents', 0 );
/**
 * Filter the query string to block the request or not
 *
 * @since 1.0
 * @return void
 **/
function secupress_block_bad_url_contents() {

	if ( empty( $_SERVER['QUERY_STRING'] ) ) {
		return;
	}

	$bad_url_contents = trim( secupress_get_module_option( 'bbq-url-content_bad-contents-list', '', 'firewall' ) );
	$bad_url_contents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_url_contents, '/' ) );

	if ( empty( $bad_url_contents ) ) {
		return;
	}

	if ( preg_match( '/' . $bad_url_contents . '/i', $_SERVER['QUERY_STRING'] ) ) {
		secupress_block( 'BUC', 503 );
	}

}