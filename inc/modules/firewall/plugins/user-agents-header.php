<?php
/**
 * Module Name: Block Bad User-Agents
 * Description: Block requests received with bad user-agents.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.4.7
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'secupress.plugins.loaded', 'secupress_block_bad_user_agents', 0 );
/**
 * Filter the user agent to block it or not
 *
 * @since 1.4.6 Strip URLs from User-Agents to prevent false positive when the website contain a bad word (which is not bad)
 * @since 1.3.1 Remove empty user agent blocking
 * @since 1.1.4 The user-agents match is case sensitive.
 * @since 1.0
 */
function secupress_block_bad_user_agents() {
	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';
	$user_agent = preg_replace( '/\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|$!:,.;]*[A-Z0-9+&@#\/%=~_|$]/i', '', $user_agent );

	if ( trim( wp_strip_all_tags( $user_agent ) ) !== trim( $user_agent ) ) {
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

	// Shellshock.
	$bad_user_agents .= ( $bad_user_agents ? '|' : '' ) . '\(.*?\)\s*\{.*?;\s*\}\s*;';

	if ( preg_match( '/' . $bad_user_agents . '/', $user_agent ) ) {
		secupress_block( 'UAHB' );
	}
}
