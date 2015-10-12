<?php
/*
Module Name: Block SQLi Scan Attempts
Description: Fool SQLi scanner/scripts to always give them a different content on each reload of the same page.
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

add_action( 'admin_footer', 'secupress_block_sqli_scanners' );
add_action( 'wp_footer', 'secupress_block_sqli_scanners' );
/**
 * Add a hidden span containing random content and random length
 *
 * @since 1.0
 * @return void
 **/
function secupress_block_sqli_scanners() {

	$md5 = md5( microtime( true ) );
	$repeat = str_repeat( chr( rand( 33, 126 ) ), (int) rand( 1, 32 ) );
	echo '<span style="display:none !important">' . $md5 . $repeat . '</span>';

}