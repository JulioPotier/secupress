<?php
/**
 * Module Name: Fix Mixed Content
 * Description: Switch every http:// to https:// in the website content
 * Main Module: ssl
 * Author: Julio Potier
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/**
 * Starts the output buffer for mixed content fix
 *
 * @since 2.2.6
 * @author Julio Potier
 **/
add_action( 'admin_init', 'secupress_ssl_mixed_content_fix_start' );
add_action( 'init', 'secupress_ssl_mixed_content_fix_start' );
function secupress_ssl_mixed_content_fix_start() {
	if ( ! preg_match( '/\.(xsl|xml)$/i', secupress_get_current_url() ) ) {
		ob_start( 'secupress_ssl_mixed_content_fix' );
	}
}

/**
 * Filter the whole site content, replacing http with https
 *
 * @since 2.3.7 Not for XLS & XML (props Aurélien Denis from SeoPress)
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $content
 * 
 * @return (string) $content
 **/
function secupress_ssl_mixed_content_fix( $content ) {
	$pattern = '/http:\/\/([^\s"\']+)/i';

	$content = preg_replace_callback(
		$pattern,
		'__secupress_ssl_mixed_content_callback',
		$content
	);

	return $content;
}

function __secupress_ssl_mixed_content_callback( $matches ) {
	if ( preg_match( '/\.(xsl|xml)$/i', $matches[1] ) ) {
		return 'http://' . $matches[1];
	}
	return 'https://' . $matches[1];
}
