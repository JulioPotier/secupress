<?php
/**
 * Module Name: Block 404 on .php
 * Description: Block requests on any .php file
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'template_redirect', 'secupress_block_404_php' );
/**
 * Block request if a 404 file if a .php one
 *
 * @since 2.1 Add filter
 * @since 2.0.1 Test file_exists to avoid fake 404 created by plugins
 * @since 1.1 Use secupress_block() instead of secupress_ban_ip()
 * @since 1.0
 * @author Julio potier
 **/
function secupress_block_404_php() {
	if ( is_404() && 'php' === pathinfo( basename( secupress_get_current_url( 'uri' ) ), PATHINFO_EXTENSION ) && ! file_exists( ABSPATH . secupress_get_current_url( 'uri' ) ) ) {
        /**
         * Gives the posibility to bypass the interdiction
         * 
         * @since 2.1
         * @author Julio Potier
         * @param (bool)
         * @param (string)
        */
        if ( ! apply_filters( 'secupress.plugins.ban_404.bypass', false, secupress_get_current_url( 'base' ) ) ) {
            secupress_block( 'PHP404', 403 );
        }
	}
}
