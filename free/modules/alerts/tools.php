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
		return [];
	}

	$emails = explode( "\n", $emails );
	$emails = array_map( 'trim', $emails );
	$emails = array_map( 'is_email', $emails );
	$emails = array_filter( $emails );

	return $emails;
}

/**
 * Return the timing for module alerts, possibly formated
 *
 * @since 2.3.18
 * @author Julio Potier
 * 
 * @param (string|int) $format 'ago' to format like "%d hours ago" ; 'int' to just get the hour number ; 'hour/s' to get the seconds ; a [timestamp] to get a readable date
 * @return (int|string)
 **/
function secupress_get_submodule_alert_timing( $format = 'int' ) {
	$timing = secupress_minmax_range( (int) apply_filters( 'secupress.plugins.module_alert.timing', 1 ), 1, 24 ); // hours
	switch ( $format ) {
	 	case 'ago': // %d hours ago
			return sprintf( _n( '%d hour ago', '%d hours ago', $timing, 'secupress' ), $timing );
 		break;
	 	
	 	case 'int':
			return $timing;
 		break;
	 	
	 	case 'hour':
	 	case 'hours':
			return $timing * HOUR_IN_SECONDS;
 		break;
	 	
	 	default: // 'at %s', just pass the timestamp into the $format param
		 	if ( ! is_int( $format ) ) {
		 		return __( 'earlier', 'secupress' );
		 	}
		 	if ( date( 'dmy', time() ) === date( 'dmy', $format ) ) { // we are the same day, just display the time
				return sprintf( _x( 'today at %s', ' a time', 'secupress' ), date_i18n( get_option( 'time_format' ), $format + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) ) );
		 	} else { // we are tomorrow, add the day
				return sprintf( _x( 'on %s at %s', 'a day and time', 'secupress' ), date_i18n( get_option( 'date_format' ), $format + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) ), date_i18n( get_option( 'time_format' ), $format + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS ) ) );
		 	}
 		break;
	}
}
