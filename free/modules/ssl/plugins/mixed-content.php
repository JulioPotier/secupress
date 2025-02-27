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
 * @author Julio Potier
 * @since 2.2.6
 **/
add_action( 'admin_init', 'secupress_ssl_mixed_content_fix_start' );
add_action( 'init', 'secupress_ssl_mixed_content_fix_start' );
function secupress_ssl_mixed_content_fix_start() {
	ob_start( 'secupress_ssl_mixed_content_fix' );
}

/**
 * Filter the whole site content, replaceing http with https
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $content
 **/
function secupress_ssl_mixed_content_fix( $content ) {
	return str_replace( 'http://', 'https://', $content );
}