<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*
 * Get available alert types.
 *
 * @since 1.0
 *
 * @param (bool) $all Set to `true` to return all free and pro types. Will return only free types otherwise.
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_alert_types_labels( $all = false ) {
	if ( ! $all ) {
		return array(
			'email' => __( 'By Email', 'secupress' ),
		);
	}

	return array(
		'email'   => __( 'By Email', 'secupress' ),
		'sms'     => __( 'By SMS', 'secupress' ),
		'push'    => __( 'By push notification', 'secupress' ),
		'slack'   => __( 'With Slack', 'secupress' ),
		'twitter' => __( 'With Twitter', 'secupress' ),
	);
}


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
