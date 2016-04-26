<?php
/*
Module Name: Block Bad User-Agents
Description: Block requests received with bad user-agents
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'secupress_plugins_loaded', 'secupress_block_bad_user_agents', 0 );
/**
 * Filter the user agent to block it or not
 *
 * @since 1.0
 */
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

	$bad_user_agents = secupress_get_module_option( 'bbq-headers_user-agents-list', '', 'firewall' );

	if ( ! empty( $bad_user_agents ) ) {
		$bad_user_agents = preg_replace( '/\s*,\s*/', '|', addcslashes( $bad_user_agents, '/' ) );
		$bad_user_agents = trim( $bad_user_agents, '| ' );

		while ( false !== strpos( $bad_user_agents, '||' ) ) {
			$bad_user_agents = str_replace( '||', '|', $bad_user_agents );
		}
	}

	if ( $bad_user_agents && preg_match( '/' . $bad_user_agents . '/i', $user_agent ) ) {
		secupress_block( 'UAHB' );
	}
}
