<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* HALP!!! ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_services_settings_callback( $settings ) {
	$settings = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return array( 'sanitized' => 1 );
	}

	secupress_require_class( 'Admin', 'Support' );
	SecuPress_Admin_Support::get_instance()->ask_support( $settings );

	return array( 'sanitized' => 1 );
}
