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
define( 'SECUPRESS_UPTIME_MONITOR_UA',  'SecuPress' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * On SecuPress or this submodule activation, start monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_uptime_monitoring_start' );
add_action( 'secupress.plugins.activation',                                         'secupress_uptime_monitoring_start' );


/**
 * On SecuPress or this submodule deactivation, stop monitoring.
 *
 * @since 1.0
 */
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_uptime_monitoring_stop' );
add_action( 'secupress.deactivation',                                                 'secupress_uptime_monitoring_stop' );


/*------------------------------------------------------------------------------------------------*/
/* UPDATE ======================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * If the consumer email address is changed, notify our server.
 *
 * @since 1.0
 */
add_action( 'secupress.added-consumer_email',   'secupress_uptime_monitoring_start' );
add_action( 'secupress.updated-consumer_email', 'secupress_uptime_monitoring_start' );
add_action( 'secupress.deleted-consumer_email', 'secupress_uptime_monitoring_stop' );


/**
 * If the notification settings are changed, notify our server.
 *
 * @since 1.0
 */
add_action( 'add_site_option_secupress_alerts_settings',    'secupress_uptime_monitoring_update_alerts_settings', 20, 2 );
add_action( 'update_site_option_secupress_alerts_settings', 'secupress_uptime_monitoring_update_alerts_settings', 20, 3 );
add_action( 'delete_site_option_secupress_alerts_settings', 'secupress_uptime_monitoring_stop' );


/**
 * When the notification settings are changed, notify our server.
 *
 * @since 1.0
 *
 * @param (string) $option   Name of the network option.
 * @param (mixed)  $newvalue Current value of the network option.
 * @param (mixed)  $oldvalue Old value of the network option.
 */
function secupress_uptime_monitoring_update_alerts_settings( $option, $newvalue, $oldvalue = false ) {
	if ( ! secupress_get_consumer_key() || ! secupress_is_submodule_active( 'alerts', 'uptime-monitoring' ) ) {
		return;
	}

	// Types of Notification.
	$new_types = isset( $newvalue['notification-types_types'] ) ? $newvalue['notification-types_types'] : array();
	$old_types = isset( $oldvalue['notification-types_types'] ) ? $oldvalue['notification-types_types'] : array();

	if ( $old_types && $new_types && $old_types !== $new_types ) {
		return secupress_uptime_monitoring_start();
	}

	$new_types = array_combine( $new_types, $new_types );

	// By Email.
	if ( isset( $new_types['email'] ) ) {
		$new = isset( $newvalue['notification-types_emails'] ) ? $newvalue['notification-types_emails'] : array();
		$old = isset( $oldvalue['notification-types_emails'] ) ? $oldvalue['notification-types_emails'] : array();

		if ( $old !== $new ) {
			return secupress_uptime_monitoring_start();
		}
	}

	// Other types.
	$types = array( 'notification-types_sms_number', 'notification-types_push', 'notification-types_slack', 'notification-types_twitter' );

	foreach ( $types as $type ) {
		if ( ! isset( $new_types[ $type ] ) ) {
			continue;
		}

		$new = isset( $newvalue[ $type ] ) ? $newvalue[ $type ] : '';
		$old = isset( $oldvalue[ $type ] ) ? $oldvalue[ $type ] : '';

		if ( $old !== $new ) {
			return secupress_uptime_monitoring_start();
		}
	}
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
	$account_token = secupress_get_option( 'uptime_monitoring_account_key' );
	$site_token    = secupress_get_option( 'uptime_monitoring_site_key' );
	$types         = secupress_get_module_option( 'notification-types_types', array(), 'alerts' );
	$methods       = array();

	if ( $types && is_array( $types ) ) {
		$build_types = array_flip( secupress_alert_types_labels( secupress_is_pro() ) );
		$types       = array_intersect( $types, $build_types );

		if ( $types ) {
			foreach ( $types as $type ) {
				$methods[ $type ] = array();

				if ( 'email' === $type ) {
					$emails = secupress_alerts_get_emails();
					$emails = array_unique( $emails );
					$methods[ $type ]['emails'] = implode( ',', $emails );
				} else {
					// SMS, push, Slack, Twitter. ////.
					$methods[ $type ];
				}
			}
		}
	}

	// Send the request.
	$response = wp_remote_post(
		SECUPRESS_UPTIME_MONITOR_URL,
		array(
			'user-agent' => SECUPRESS_UPTIME_MONITOR_UA,
			'timeout'	 => 10,
			'body'       => array(
				'url'           => esc_url( home_url() ),
				'email'         => secupress_get_consumer_email(),
				'account_token' => esc_attr( $account_token ),
				'site_token'    => esc_attr( $site_token ),
				'source'        => SECUPRESS_UPTIME_MONITOR_UA,
				'methods'       => wp_json_encode( $methods ),
			),
		)
	);

	// Error?
	$new_tokens = secupress_uptime_monitoring_connection_succeeded( $response );

	if ( ! $new_tokens ) {
		return;
	}

	// Store the tokens.
	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$options = is_array( $options ) ? $options : array();
	$update  = false;

	if ( $account_token !== $new_tokens['account_token'] ) {
		$options['uptime_monitoring_account_token'] = $new_tokens['account_token'];
		$update = true;
	}

	if ( $site_token !== $new_tokens['site_token'] ) {
		$options['uptime_monitoring_site_token'] = $new_tokens['site_token'];
		$update = true;
	}

	if ( $update ) {
		update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
	}
}


/**
 * Stop monitoring.
 *
 * @since 1.0
 */
function secupress_uptime_monitoring_stop() {
	$account_token = secupress_get_option( 'uptime_monitoring_account_key' );
	$site_token    = secupress_get_option( 'uptime_monitoring_site_key' );

	// Send the request.
	$response = wp_remote_request(
		SECUPRESS_UPTIME_MONITOR_URL,
		array(
			'method'     => 'PUT',
			'user-agent' => SECUPRESS_UPTIME_MONITOR_UA,
			'timeout'	 => 10,
			'body'       => array(
				'pause'         => 1,
				'url'           => esc_url( home_url() ),
				'email'         => secupress_get_consumer_email(),
				'account_token' => esc_attr( $account_token ),
				'site_token'    => esc_attr( $site_token ),
				'source'        => SECUPRESS_UPTIME_MONITOR_UA,
			),
		)
	);

	// Error?
	secupress_uptime_monitoring_connection_succeeded( $response, 'stop' );
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Handle monitoring connection failure.
 * If the request fails, or if the distant server doesn't return an HTTP code 200, or if an error status is returned: an error is triggered.
 * In that case, the submodule will also be re-activated or re-deactivated, depending of the previous status.
 *
 * @since 1.0
 *
 * @param (WP_Error|array) $response The request response array or WP_Error object on failure.
 * @param (string)         $type     What we're doing: "start" or "stop" monitoring.
 *
 * @return (string|bool) The token on success. False if an error occured.
 */
function secupress_uptime_monitoring_connection_succeeded( $response, $type = 'start' ) {

	// Error during the request itself.
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

	// The distant server is down (or something).
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

	// Check the response body.
	$data = wp_remote_retrieve_body( $response );
	$data = json_decode( $data );

	if ( ! is_object( $data ) || empty( $data->status ) || 'success' !== $data->status || empty( $data->account_token ) || empty( $data->site_token ) ) {

		if ( 'start' === $type ) {
			secupress_deactivate_submodule_silently( 'alerts', 'uptime-monitoring' );
		} else {
			secupress_activate_submodule_silently( 'alerts', 'uptime-monitoring' );
		}

		$message = __( '<strong>Error:</strong> the Monitor server returned an error status. Please try again in few minutes or contact our support team.', 'secupress' );
		add_settings_error( 'general', 'monitor_start_monitor_server_error', $message, 'error' );
		return false;
	}

	// Return the tokens.
	return array(
		'account_token' => sanitize_text_field( $data->account_token ),
		'site_token'    => sanitize_text_field( $data->site_token ),
	);
}
