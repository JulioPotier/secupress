<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get available alert types.
 *
 * @since 1.0
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_alert_types_labels() {

	return array(
		'email'   => __( 'Email', 'secupress' ),
		// 'twitter' => __( 'Twitter', 'secupress' ), ////
		// 'slack'   => __( 'Slack', 'secupress' ), ////
		// 'sms'     => __( 'SMS', 'secupress' ), ////
		// 'push'    => __( 'Push notification', 'secupress' ), ////
	);
}


/**
 * Get email addresses set by the user in the settings.
 *
 * @since 1.0
 *
 * @return (array) An array of valid email addresses.
 */
function secupress_alerts_get_emails() {
	$emails = secupress_get_module_option( 'notification-types_emails', '', 'alerts' );

	if ( ! $emails ) {
		return array();
	}

	$emails = explode( "\n", $emails );
	$emails = array_map( 'trim', $emails );
	$emails = array_map( 'is_email', $emails );
	$emails = array_filter( $emails );

	return $emails;
}
