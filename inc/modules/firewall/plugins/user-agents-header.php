<?php
/*
Module Name: Block Bad User-Agents
Description: Block requests received with bad user-agents
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
add_action( 'secupress_plugins_loaded', 'secupress_block_bad_user_agents', 0 );
/**
 * Filter the user agent to block it or not
 *
 * @since 1.0
 * @return void
 **/
function secupress_block_bad_user_agents() {
	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';

	if ( ! $user_agent ) {
		secupress_block( 'UAHE' );
	}

	if ( strlen( $user_agent ) > 255 ) {
		secupress_block( 'UAHL' );
	}

	if ( wp_strip_all_tags( $user_agent, true ) !== $user_agent ) {
		secupress_block( 'UAHT' );
	}

	$bad_user_agents = trim( secupress_get_module_option( 'bbq-headers_user-agents-list', '', 'firewall' ) );
	$bad_user_agents = preg_replace( '/\s*,\s*/', '|', preg_quote( $bad_user_agents, '/' ) );

	if ( $bad_user_agents && preg_match( '/' . $bad_user_agents . '/i', $user_agent ) ) {
		secupress_block( 'UAHB' );
	}

}