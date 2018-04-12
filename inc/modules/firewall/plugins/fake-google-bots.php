<?php
/**
 * Module Name: Block Fake GoogleBots
 * Description: Block requests from fake bots
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Returns if the user-agent is a fake bot or not.
 *
 * @return (bool) true mean the IP is a good bot, false is a fake bot.
 * @since 1.4
 *
 * @author Julio Potier
 **/
function secupress_check_bot_ip() {
	$ip         = secupress_get_ip();
	$hostname   = gethostbyaddr( $ip );
	$real_ip    = gethostbyname( $hostname );
	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';

	if ( $hostname === $ip ) {
		return false;
	}

	if ( $ip === $real_ip ) {

		if ( preg_match( '/bingbot|msnbot/i', $user_agent ) && ( preg_match( '/msn\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/Google/i', $user_agent ) && ( preg_match( '/Google\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/slurp/i', $user_agent ) && ( preg_match( '/yahoo\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/DuckDuckBot/i', $user_agent ) && ( preg_match( '/DuckDuckGo\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/Baiduspider/i', $user_agent ) && ( preg_match( '/baidu\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/YandexBot/i', $user_agent ) && ( preg_match( '/yandex\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/facebot|facebook/i', $user_agent ) && ( preg_match( '/facebook\.com/i', $hostname ) ) ) {
			return true;
		}
		if ( preg_match( '/ia_archiver/i', $user_agent ) && ( preg_match( '/alexa\.com/i', $hostname ) ) ) {
			return true;
		}

		preg_match( '/([\w]+\.[\w]+)($|\.uk$)/', strtolower( $hostname ), $matches );

		$domain = $matches[0];

		if ( ! ( strpos( $user_agent, $domain ) !== false ) ) {
			return false;
		}

		return true;
	}
	return false;
}

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
	// Is a bot if true.
	$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? trim( $_SERVER['HTTP_USER_AGENT'] ) : '';

	if ( ! preg_match( '/curl|fetch|crawler|bot|spider|slurp|archiver|google|bing|yahoo/i', $user_agent ) ) {
		return;
	}

	if ( ! secupress_check_bot_ip() ) {
		secupress_block( 'FBOT', 403 );
	}
}
