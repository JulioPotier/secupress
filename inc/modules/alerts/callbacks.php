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

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// Activate/deactivate.
	if ( empty( $settings['alerts_type'] ) || ! is_array( $settings['alerts_type'] ) ) {
		$settings['alerts_type'] = array();
	} else {
		$types = array_flip( secupress_alerts_labels( secupress_is_pro() ) );

		$settings['alerts_type'] = array_intersect( $settings['alerts_type'], $types );
	}

	secupress_manage_submodule( $modulenow, 'alerts', ! empty( $settings['alerts_type'] ) );

	// Email
	if ( ! empty( $settings['alerts_email'] ) ) {
		$settings['alerts_email'] = explode( ',', $settings['alerts_email'] );
		$settings['alerts_email'] = array_map( 'trim', $settings['alerts_email'] );
		$settings['alerts_email'] = array_map( 'is_email', $settings['alerts_email'] );
		$settings['alerts_email'] = array_filter( $settings['alerts_email'] );
		if ( $settings['alerts_email'] ) {
			if ( ! secupress_is_pro() ) {
				$settings['alerts_email'] = reset( $settings['alerts_email'] );
			} else {
				$settings['alerts_email'] = implode( ', ', $settings['alerts_email'] );
			}
		} else {
			unset( $settings['alerts_email'] );
		}
	} else {
		unset( $settings['alerts_email'] );
	}

	// Other types
	$types = array( 'alerts_sms_number', 'alerts_push', 'alerts_slack', 'alerts_twitter' );

	foreach ( $types as $type ) {
		if ( ! empty( $settings[ $type ] ) ) {
			$settings[ $type ] = sanitize_text_field( $settings[ $type ] );
		} else {
			unset( $settings[ $type ] );
		}
	}

	// Frequency
	$settings['alerts_frequency'] = secupress_minmax_range( $settings['alerts_frequency'], 5, 60 );

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Get available alert types.
 *
 * @since 1.0
 *
 * @param (bool) $all Set to `true` to return all free and pro types. Will return only free types otherwise.
 *
 * @return (array) Return an array with identifiers as keys and field labels as values.
 */
function secupress_alerts_labels( $all = false ) {
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
