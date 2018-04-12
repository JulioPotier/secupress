<?php
/**
 * Module Name: Block SQLi Scan Attempts
 * Description: Fool SQLi scanner/scripts to always give them different content on each reload of the same page.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'admin_footer', 'secupress_block_sqli_scanners' );
add_action( 'wp_footer', 'secupress_block_sqli_scanners' );
/**
 * Add a hidden span containing random content and random length
 *
 * @since 1.4 Usage of a Lorem to prevent Google to tag the page as "hacked"
 * @since 1.0
 */
function secupress_block_sqli_scanners() {
	$lorem = explode( ' ', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam justo velit, commodo id facilisis id, pulvinar at neque. Nullam non felis ut felis fringilla porta. Curabitur libero sem, mattis nec risus quis, tempus suscipit leo. Aenean luctus diam eget leo venenatis, quis commodo nunc efficitur. Phasellus ut libero dolor. Sed eleifend mattis odio ut consequat. Donec ut elementum libero. Donec sed massa vulputate, ultricies lectus et, tristique elit. Praesent ipsum mi, accumsan id dictum vel, dapibus in ante. Praesent ut venenatis risus.' );
	shuffle( $lorem );
	$lorem = array_slice( $lorem, (int) rand( 6, 12 ), (int) rand( 6, 12 ) );
	$lorem = implode( ' ', $lorem );
	echo '<span style="display:none !important">' . $lorem . '</span>';
}
