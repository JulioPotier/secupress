<?php
/**
 * Module Name: Block Bad User-Agents
 * Description: Block requests received with bad user-agents.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.4.7
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'secupress.plugins.loaded', 'secupress_block_bad_user_agents', 5 );
/**
 * Filter the user agent to block it or not
 *
 * @since 2.0 Empty user agent is fine
 * @since 1.4.6 Strip URLs from User-Agents to prevent false positive when the website contain a bad word (which is not bad)
 * @since 1.3.1 Remove empty user agent blocking
 * @since 1.1.4 The user-agents match is case sensitive.
 * @since 1.0
 */
function secupress_block_bad_user_agents() {
	// If this is from our scanner and the host remove or empty the UA, return a good result
	if ( isset( $_SERVER['HTTP_X_SECUPRESS_ORIGIN'] ) && 'SecuPress_Scan_Bad_User_Agent' === $_SERVER['HTTP_X_SECUPRESS_ORIGIN'] && ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) || empty( $_SERVER['HTTP_USER_AGENT'] ) ) ) {
		status_header( 200, 'OK' );
		echo 'SecuPress_Scan_Bad_User_Agent OK';
		die();
	}

	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';
	// Empty is fine, can't harm anything.
	if ( empty( $user_agent ) ) {
		return;
	}

	$user_agent = preg_replace( '/\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|$!:,.;]*[A-Z0-9+&@#\/%=~_|$]/i', '', $user_agent );

	if ( trim( wp_strip_all_tags( $user_agent ) ) !== trim( $user_agent ) ) {
		secupress_block( 'UAHT', [ 'code' => 403, 'b64' => [ 'data' => $user_agent ] ] );
	}

	$bad_user_agents = secupress_get_module_option( 'bbq-headers_user-agents-list', '', 'firewall' );

	if ( ! empty( $bad_user_agents ) ) {
		$bad_user_agents = preg_replace( '#\s*,\s*#', '|', preg_quote( $bad_user_agents ) );
		$bad_user_agents = trim( $bad_user_agents, '| ' );

		while ( false !== strpos( $bad_user_agents, '||' ) ) {
			$bad_user_agents = str_replace( '||', '|', $bad_user_agents );
		}
	}

	// Shellshock.
	$bad_user_agents .= ( $bad_user_agents ? '|' : '' ) . '\(.*?\)\s*\{.*?;\s*\}\s*;';

	preg_match( '#' . $bad_user_agents . '#', $user_agent, $matches );
	if ( ! empty( $matches ) ) {
		secupress_block( 'UAHB', [ 'code' => 403, 'b64' => [ 'data' => $matches ] ] );
	}
}
