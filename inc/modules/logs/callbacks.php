<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Activate or deactivate "action" Logs.
 *
 * @since 1.0
 **/
add_action( 'admin_post_secupress_activate_action_logs', '__secupress_activate_action_logs' );

function __secupress_activate_action_logs() {
	// Make all security tests.
	check_admin_referer( 'secupress_activate_action_logs' );
	secupress_check_user_capability();

	// (De)Activate.
	$activate = ! empty( $_POST['secupress-plugin-activation']['action-logs_activated'] );
	secupress_manage_submodule( 'logs', 'action-logs', $activate );

	// Redirect.
	wp_redirect( wp_get_referer() );
	die();
}


/**
 * Activate or deactivate "404" Logs.
 *
 * @since 1.0
 **/
add_action( 'admin_post_secupress_activate_404_logs', '__secupress_activate_404_logs' );

function __secupress_activate_404_logs() {
	// Make all security tests.
	check_admin_referer( 'secupress_activate_404_logs' );
	secupress_check_user_capability();

	// (De)Activate.
	$activate = ! empty( $_POST['secupress-plugin-activation']['404-logs_activated'] );
	secupress_manage_submodule( 'logs', '404-logs', $activate );

	// Redirect.
	wp_redirect( wp_get_referer() );
	die();
}
