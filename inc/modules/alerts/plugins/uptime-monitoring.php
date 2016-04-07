<?php
/*
Module Name: Uptime Monitoring
Description: Receive an email notification when your website is down.
Main Module: alerts
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
 * On SecuPress or this submodule activation, start monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress_activate_plugin_uptime-monitoring', 'secupress_uptime_monitoring_start' );
add_action( 'secupress.plugins.activation',                'secupress_uptime_monitoring_start' );


/**
 * On SecuPress or this submodule deactivation, stop monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress_deactivate_plugin_uptime-monitoring', 'secupress_uptime_monitoring_deactivate' );
add_action( 'secupress_deactivation',                        'secupress_uptime_monitoring_deactivate' );


/**
 * Maybe stop monitoring.
 *
 * @since 1.0
 *
 * @param (array) $args Some parameters.
 */
function secupress_uptime_monitoring_deactivate( $args = array() ) {
	if ( empty( $args['no-tests'] ) ) {
		secupress_uptime_monitoring_stop();
	}
}


/*------------------------------------------------------------------------------------------------*/
/* UPDATE ======================================================================================= */
/*------------------------------------------------------------------------------------------------*/
/**
 * If the email address is changed, start monitoring.
 * Since this email address is set on SecuPress installation and never changes, this should be useless.
 *
 * @since 1.0
 */
add_action( 'pre_update_option_' . SECUPRESS_SETTINGS_SLUG, 'secupress_uptime_monitoring_pre_update_email', 10, 2 );

function secupress_uptime_monitoring_pre_update_email( $newvalue, $oldvalue ) {
	if ( $oldvalue['consumer_email'] !== $newvalue['consumer_email'] ) {
		secupress_uptime_monitoring_start();
	}

	return $newvalue;
}


/*------------------------------------------------------------------------------------------------*/
/* START OR STOP THE SERVICE ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Start monitoring.
 *
 * @since 1.0
 */
function secupress_uptime_monitoring_start() {
	$token  = secupress_get_module_option( 'uptime-monitoring-token', false, 'alerts' );
	// Guess the action: if the token exists, "update". "add" otherwise.
	$action = $token ? 'update' : 'add';

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

	// Error?
	if ( ! secupress_uptime_monitoring_connexion_succeeded( $response ) ) {
		return;
	}

	// Store a token if it's a new subscription.
	if ( 'add' === $action ) {
		$data = wp_remote_retrieve_body( $response );
		$data = json_decode( $data );

		if ( is_object( $data ) && ! empty( $data->status ) && 'success' === $data->status ) {
			// Save the token.
			secupress_update_module_option( 'uptime-monitoring-token', $data->token, 'alerts' );
		} else {
			// Trigger an error and re-deactivate the submodule.
			secupress_deactivate_submodule_silently( 'alerts', 'uptime-monitoring' );

			$message = __( '<strong>Error:</strong> the monitoring couldn\'t be activated. Please contact our support.', 'secupress' );
			add_settings_error( 'general', 'monitor_token_failed', $message, 'error' );
		}
	}
}


/**
 * Stop monitoring.
 *
 * @since 1.0
 */
function secupress_uptime_monitoring_stop() {
	$token = secupress_get_module_option( 'uptime-monitoring-token', false, 'alerts' );

	// Send the request.
	$response = wp_remote_post(
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

	// Error?
	secupress_uptime_monitoring_connexion_succeeded( $response, 'stop' );
}


/**
 * Handle monitoring connexion failure.
 * If the request fails or if the distant server doesn't return an HTTP code 200, an error is triggered.
 * In that case, the submodule will also be re-activated or re-deactivated, depending of the previous status.
 *
 * @since 1.0
 *
 * @param (WP_Error|array) $response The request response array or WP_Error object on failure.
 * @param (string)         $type     What we're doing: "start" or "stop" monitoring.
 *
 * @return (bool) False if an error occured. True otherwise.
 */
function secupress_uptime_monitoring_connexion_succeeded( $response, $type = 'start' ) {

	if ( is_wp_error( $response ) ) {

		if ( 'start' === $type ) {
			secupress_deactivate_submodule_silently( 'alerts', 'uptime-monitoring' );
		} else {
			secupress_activate_submodule_silently( 'alerts', 'uptime-monitoring' );
		}

		$message = __( '<strong>Error:</strong> couldn\'t call the Monitor server. Please try again in few minutes.', 'secupress' );
		add_settings_error( 'general', 'monitor_start_wp_error', $message, 'error' );
		return false;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {

		if ( 'start' === $type ) {
			secupress_deactivate_submodule_silently( 'alerts', 'uptime-monitoring' );
		} else {
			secupress_activate_submodule_silently( 'alerts', 'uptime-monitoring' );
		}

		$message = __( '<strong>Error:</strong> the Monitor server is not available. Please try again in few minutes.', 'secupress' );
		add_settings_error( 'general', 'monitor_start_monitor_server_error', $message, 'error' );
		return false;
	}

	return true;
}
