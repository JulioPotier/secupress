<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Check whether the plugin is active by checking the active_plugins list.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active( $plugin )
{
	return in_array( $plugin, (array) get_option( 'active_plugins', array() ) ) || secupress_is_plugin_active_for_network( $plugin );
}

/**
 * Check whether the plugin is active for the entire network.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active_for_network( $plugin )
{
	if ( ! is_multisite() ) {
		return false;
	}

	$plugins = get_site_option( 'active_sitewide_plugins');

	return isset( $plugins[ $plugin ] );
}
