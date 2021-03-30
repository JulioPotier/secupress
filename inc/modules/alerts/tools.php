<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

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
