<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Check whether the plugin is active by checking the active_plugins list.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active( $plugin ) {
	return in_array( $plugin, (array) get_option( 'active_plugins', array() ) ) || secupress_is_plugin_active_for_network( $plugin );
}


/**
 * Check whether the plugin is active for the entire network.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active_for_network( $plugin ) {
	if ( ! is_multisite() ) {
		return false;
	}

	$plugins = get_site_option( 'active_sitewide_plugins' );

	return isset( $plugins[ $plugin ] );
}


function secupress_is_submodule_active( $submodule, $module = null ) {
	return in_array_deep( $module . '_plugin_' . $submodule, get_site_option( SECUPRESS_ACTIVE_SUBMODULES ) );
}


/**
 * @return (-1)/(bool) -1 = every role is affected, true = the user's role is affected, false = the user's role isn't affected.
 */
function secupress_is_affected_role( $module, $submodule, $user ) {
	$roles = secupress_get_module_option( $submodule . '_affected_role', array(), $module );

	if ( ! $roles ) {
		return -1;
	}

	return is_a( $user, 'WP_User' ) && user_can( $user, 'exist' ) && ! count( (array) array_intersect( $roles, $user->roles ) );
}


function secupress_validate_range( $value, $min, $max ) {
	return filter_var( $value, FILTER_VALIDATE_INT, array( 'options' => array( 'min_range' => $min, 'max_range' => $max ) ) );
}
