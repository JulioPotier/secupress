<?php
/*
Module Name: Uptime Monitoring
Description: Receive an email notification when your website is down.
Main Module: tools
Author: SecuPress
Version: 1.0
*/
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

define( 'SECUPRESS_UPTIME_MONITOR_URL', 'https://support.wp-rocket.me/api/monitoring/process.php' );
define( 'SECUPRESS_UPTIME_MONITOR_UA',  'WP-Rocket' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * On SecuPress activation and this plugin activation, start monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress_activate_plugin_uptime-monitoring', 'secupress_uptime_monitoring_start' );
add_action( 'secupress.plugins.activation',                'secupress_uptime_monitoring_start' );


/**
 * If the email address is changed, start monitoring.
 * Since this email address is set on SecuPress installation and never changes, this should be useless.
 *
 * @since 1.0
 */
add_action( 'pre_update_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_uptime_monitoring_pre_update_email', 10, 2 );

function secupress_uptime_monitoring_pre_update_email( $newvalue, $oldvalue ) {
	if ( $oldvalue['consumer_email'] !== $newvalue['consumer_email'] ) {
		$action = empty( $oldvalue['consumer_email'] ) ? 'add' : 'update';
		secupress_uptime_monitoring_start( $action );
	}

	return $newvalue;
}


/**
 * On SecuPress deactivation and this plugin deactivation, stop monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress_deactivate_plugin_uptime-monitoring', 'secupress_uptime_monitoring_stop' );
add_action( 'secupress_deactivation',                        'secupress_uptime_monitoring_stop' );


/*------------------------------------------------------------------------------------------------*/
/* START OR STOP THE SERVICE ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Start monitoring.
 *
 * @since 1.0
 *
 * @param (string) $action Possible values are "add" and "update". This is used by the monitoring service.
 */
function secupress_uptime_monitoring_start( $action = null ) {
	$token = secupress_get_module_option( 'uptime-monitoring-token', false, 'tools' );

	// If the action is not provided, guess the value: if the token exists, "update".
	if ( 'add' !== $action && 'update' !== $action ) {
		$action = $token ? 'update' : 'add';
	}

	// Send the request.
	$response = wp_remote_post(
		SECUPRESS_UPTIME_MONITOR_URL,
		array(
			'user-agent' => SECUPRESS_UPTIME_MONITOR_UA,
			'timeout'	 => 10,
			'body'       => array(
				'action' => $action,
				'url'    => home_url(),
				'email'  => sanitize_email( secupress_get_option( 'consumer_email' ) ),
				'token'  => $token,
				'source' => 'SecuPress',
			)
		)
	);

	// Store a token if it's a new subscription or if the token has been deleted.
	if ( 'add' === $action || ! $token ) {
		$data = wp_remote_retrieve_body( $response );
		$data = json_decode( $data );

		if ( is_object( $data ) && ! empty( $data->status ) && 'success' === $data->status ) {
			secupress_update_module_option( 'uptime-monitoring-token', $data->token, 'tools' );
		}
	}
}


/**
 * Stop monitoring.
 *
 * @since 1.0
 */
function secupress_uptime_monitoring_stop() {
	$token = secupress_get_module_option( 'uptime-monitoring-token', false, 'tools' );

	// Send the request.
	wp_remote_post(
		SECUPRESS_UPTIME_MONITOR_URL,
		array(
			'user-agent' => SECUPRESS_UPTIME_MONITOR_UA,
			'timeout'	 => 10,
			'body'       => array(
				'action' => 'delete',
				'url'    => home_url(),
				'token'  => $token,
				'source' => 'SecuPress',
			)
		)
	);
}
