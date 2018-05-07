<?php
/**
 * Module Name: Block Fake GoogleBots
 * Description: Block requests from fake bots
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'plugins_loaded', 'secupress_check_fake_bot' );
/**
 * Block the request is this is a fake bot one.
 *
 * @return (void)
 * @since 1.4
 *
 * @author Julio Potier
 **/
function secupress_check_fake_bot() {
	if ( ! secupress_check_bot_ip( true ) ) {
		return;
	}
	// Is a bot if true.
	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';

	if ( ! preg_match( '/yandexbot|duckduckbot|slurp|baiduspider|facebot|facebook|ia_archiver|google|bingbot|msnbot/i', $user_agent ) ) {
		return;
	}

	if ( ! secupress_check_bot_ip() ) {
		secupress_block( 'FAKEBOT', 403 );
	}
}
