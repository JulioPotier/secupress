<?php
/**
 * Module Name: Ban 404 on .php
 * Description: Ban requests on any .php file
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'template_redirect', 'secupress_ban_404_php' );
function secupress_ban_404_php() {
	if ( is_404() && 'php' === pathinfo( basename( secupress_get_current_url( 'uri' ) ), PATHINFO_EXTENSION ) ) {
		secupress_block( 'PHP404' );
	}
}