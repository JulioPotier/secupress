<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MODULE OPTIONS ============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Delete a SecuPress module option.
 *
 * @since 1.4.4
 *
 * @param (string) $module  The module slug (see array keys from `modules.php`).
 */
function secupress_delete_module_option( $module ) {
	global $wpdb;
	delete_site_option( "secupress_{$module}_settings" );
	delete_site_transient( 'secupress_active_submodules' );
	$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . $wpdb->options . ' WHERE option_name LIKE "secupress_active_submodule_%" AND option_value = %s', $module ) );
}

/**
 * Update a SecuPress module option.
 *
 * @since 1.0
 *
 * @param (string) $option  The option name.
 * @param (mixed)  $value   The new value.
 * @param (string) $module  The module slug (see array keys from `modules.php`). Default is the current module.
 */
function secupress_update_module_option( $option, $value, $module = false ) {
	if ( ! $module ) {
		$module = secupress_get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options[ $option ] = $value;

	update_site_option( "secupress_{$module}_settings", $options );
}


/**
 * Update a SecuPress module options.
 *
 * @since 1.0
 *
 * @param (array)  $values The new values. Keys not provided are not removed, previous values are kept.
 * @param (string) $module The module slug (see array keys from `modules.php`). Default is the current module.
 */
function secupress_update_module_options( $values, $module = false ) {
	if ( ! $values || ! is_array( $values ) ) {
		return null;
	}

	if ( ! $module ) {
		$module = secupress_get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options = array_merge( $options, $values );

	update_site_option( "secupress_{$module}_settings", $options );
}
