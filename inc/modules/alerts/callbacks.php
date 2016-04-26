<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function __secupress_alerts_settings_callback( $settings ) {
	$modulenow = 'alerts';
	$settings  = $settings ? $settings : array();
	$activate  = secupress_get_submodule_activations( $modulenow );

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// Types of Notification.
	__secupress_types_of_notification_settings_callback( $modulenow, $settings );

	// Event Alerts.
	__secupress_event_alerts_settings_callback( $modulenow, $settings, $activate );

	// Uptime monitoring.
	__secupress_uptime_monitoring_settings_callback( $modulenow, $settings, $activate );

	return $settings;
}


/**
 * Types of Notification Callback.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_types_of_notification_settings_callback( $modulenow, &$settings ) {
	// API check: the free API only needs an email address.
	if ( ! secupress_get_consumer_email() ) {
		$settings = array( 'sanitized' => 1 );
		return;
	}

	// Types.
	if ( empty( $settings['notification-types_types'] ) || ! is_array( $settings['notification-types_types'] ) ) {
		unset( $settings['notification-types_types'] );
		$types = array();
	} else {
		$types = array_flip( secupress_alert_types_labels( secupress_is_pro() ) );
		$settings['notification-types_types'] = array_intersect( $settings['notification-types_types'], $types );
		$types = array_flip( $settings['notification-types_types'] );
	}

	// Types credentials.

	// Emails.
	$all_emails = array();

	if ( ! empty( $settings['notification-types_emails'] ) ) {
		$settings['notification-types_emails'] = explode( "\n", $settings['notification-types_emails'] );
		$settings['notification-types_emails'] = array_map( 'trim', $settings['notification-types_emails'] );
		$settings['notification-types_emails'] = array_map( 'is_email', $settings['notification-types_emails'] );
		$settings['notification-types_emails'] = array_filter( $settings['notification-types_emails'] );
		$settings['notification-types_emails'] = array_flip( array_flip( $settings['notification-types_emails'] ) );
		natcasesort( $settings['notification-types_emails'] );
		$all_emails = $settings['notification-types_emails'];
		$settings['notification-types_emails'] = implode( "\n", $settings['notification-types_emails'] );
	}

	if ( empty( $settings['notification-types_emails'] ) ) {
		unset( $settings['notification-types_emails'] );
	}

	// We ask at least 2 email addresses.
	if ( isset( $types['email'] ) && count( $all_emails ) < 2 ) {
		$key = array_search( 'email', $settings['notification-types_types'] );

		if ( false !== $key ) {
			unset( $settings['notification-types_types'][ $key ] );
			$settings['notification-types_types'] = array_values( $settings['notification-types_types'] );

			$message = __( 'Notifications by email require at least two addresses.', 'secupress' );
			add_settings_error( 'general', 'notifications-email-min-number-addresses', $message, 'error' );
		}
	}

	// Other types.
	$types = array( 'notification-types_sms_number', 'notification-types_push', 'notification-types_slack', 'notification-types_twitter' );

	foreach ( $types as $type ) {
		if ( ! empty( $settings[ $type ] ) ) {
			$settings[ $type ] = sanitize_text_field( $settings[ $type ] );
		} else {
			unset( $settings[ $type ] );
		}
	}
}


/**
 * Event Alerts Callback.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_event_alerts_settings_callback( $modulenow, &$settings, $activate ) {
	// Activate/deactivate.
	secupress_manage_submodule( $modulenow, 'alerts', ! empty( $activate['alerts_activated'] ) && ! empty( $settings['notification-types_types'] ) );

	// Frequency.
	if ( empty( $settings['alerts_frequency'] ) || ! is_numeric( $settings['alerts_frequency'] ) ) {
		$settings['alerts_frequency'] = 15;
	} else {
		$settings['alerts_frequency'] = secupress_minmax_range( $settings['alerts_frequency'], 5, 60 );
	}
}


/**
 * Uptime Monitor Callback.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_uptime_monitoring_settings_callback( $modulenow, &$settings, $activate ) {
	// Activate/deactivate.
	secupress_manage_submodule( $modulenow, 'uptime-monitoring', ! empty( $activate['monitoring_activated'] ) && ! empty( $settings['notification-types_types'] ) );
}
