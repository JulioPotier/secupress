<?php
/**
 * Module Name: Block 404 on .php
 * Description: Block requests on any .php file
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'template_redirect', 'secupress_block_404_php' );
/**
 * Block request if a 404 file if a .php one
 *
 * @since 1.1 Use secupress_block() instead of secupress_ban_ip()
 * @since 1.0
 * @author Julio potier
 **/
function secupress_block_404_php() {
	if ( is_404() && 'php' === pathinfo( basename( secupress_get_current_url( 'uri' ) ), PATHINFO_EXTENSION ) ) {
		secupress_block( 'PHP404', 403 );
	}
}
