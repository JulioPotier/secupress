<?php
/*
Module Name: Non-Login Time Slot
Description: Define a time slot when noone can log in.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'plugins_loaded', 'secupress_donttrytologin' );
function secupress_donttrytologin() {
	$timings = secupress_get_module_option( 'login-protection_nonlogintimeslot', false, 'users-login' );

	if ( false === $timings ) {
		return;
	}
	
	// server hour
	$UTC        = new DateTimeZone( 'UTC' );
	$newTZ      = new DateTimeZone( ini_get( 'date.timezone' ) );
	$date       = new DateTime( '', $UTC );
	$date->setTimezone( $newTZ );
	$server_hour = strtotime( $date->format( 'Y-m-d H:i:s' ) );

	// from
	$setting_from     = strtotime( date( sprintf( 'Y-m-d %s:%s:00', $timings['from_hour'], $timings['from_minute'] ) ) );

	// to
	$setting_to     = strtotime( date( sprintf( 'Y-m-d %s:%s:00', $timings['to_hour'], $timings['to_minute'] ) ) );

	if ( ( $setting_from < $setting_to ) && ( ( $server_hour > $setting_from ) && ( $server_hour < $setting_to ) ) ||
		 ( $setting_from > $setting_to ) && ( ( $server_hour > $setting_from ) || ( $server_hour < $setting_to ) ) ) {
		add_action( 'login_form_login', '__secupress_cant_login_now' );
		remove_all_filters( 'authenticate' );
		add_filter( 'authenticate', '__return_false', PHP_INT_MAX );
	}
}

function __secupress_cant_login_now() {
	login_header( __( 'You can\'t log in now.', 'secupress' ), '<p class="message">' . __( 'For security reasons, the login page is disabled for the moment, please come back later.', 'secupress' ) . '</p>' );
	login_footer();
	die();
}