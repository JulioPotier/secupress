<?php
/**
 * Module Name: Block Fake GoogleBots
 * Description: Block requests from fake bots
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

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

	$user_agent_regex_test_list = [ 'yandexbot', 'duckduckbot', 'slurp', 'baiduspider', 'facebot', 'facebook', 'ia_archiver', 'google', 'bingbot', 'msnbot' ];
	/**
	 * Filter to modify the user agents test list
	 *
	 * @since 1.4.3
	 *
	 * @param (array) $user_agent_regex_test_list The list to be filtered.
	 */
	$user_agent_regex_test_list = apply_filters( 'secupress.fake_bot_ua_list', $user_agent_regex_test_list );

	$user_agent_regex_not_list = [ 'facebookexternalhit' ];
	/**
	 * Filter to modify the user agents not ok list
	 *
	 * @since 1.4.4
	 *
	 * @param (array) $user_agent_regex_not_list The list to be filtered.
	 */
	$user_agent_regex_not_list = apply_filters( 'secupress.fake_bot_ua_not_list', $user_agent_regex_test_list );

	if ( ! preg_match( '/' . implode( '|', $user_agent_regex_test_list ) . '/i', $user_agent )
	 || preg_match( '/' . implode( '|', $user_agent_regex_not_list ) . '/i', $user_agent )
		) {
		return;
	}

	if ( ! secupress_check_bot_ip() ) {
		secupress_block( 'FAKEBOT', [ 'code' => 403, 'b64' => [ 'data' => $user_agent ] ] );
	}
}
