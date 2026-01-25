<?php
/**
 * Plugin Name: {{PLUGIN_NAME}} No Plugin Installations
 * Description: Filters the active plugin option to prevent loading other ones.
 * Version: 2.3.17
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2025 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( defined( 'SECUPRESS_NO_PLUGIN_ACTION_RUNNING' ) ) {
	@unlink( __FILE__ ); // We are in a duplicated file, should not happen, delete us!
	return;
}

define( 'SECUPRESS_INSTALLED_PLUGINS'       , '_secupress_installed_plugins' );
define( 'SECUPRESS_INSTALLED_MUPLUGINS'     , '_secupress_installed_muplugins' );
define( 'SECUPRESS_ACTIVE_PLUGINS'          , '_secupress_active_plugins' );

define( 'SECUPRESS_NO_PLUGIN_ACTION_RUNNING', true );
$GLOBALS['SECUPRESS_EXPERT_MODULES_ON']['plugin_actions'] = true;

if ( is_multisite() ) {
	define( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK'  , '_secupress_active_sitewide_plugins' );
	add_filter( 'pre_site_option_active_sitewide_plugins', 'secupress_no_action_filter_active_plugins_network' );
	/**
	 * Return our active plugins list
	 *
	 * @since 2.2.6
	 * @author Julio Potier
	 * @return (array) $active_plugins
	 **/
	function secupress_no_action_filter_active_plugins_network( $pre ) {
		$plugins = get_site_option( SECUPRESS_ACTIVE_PLUGINS_NETWORK, null );
		if ( is_null( $plugins ) ) {
			defined( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK_ERROR' ) || define( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK_ERROR', true );
			return $pre;
		}
		return $plugins;
	}
}

add_filter( 'pre_option_active_plugins', 'secupress_no_action_filter_active_plugins' );
/**
 * Return our active plugins list
 *
 * @since 2.2.6
 * @author Julio Potier
 * @return (array) $active_plugins
 **/
function secupress_no_action_filter_active_plugins( $pre ) {
	$plugins = get_option( SECUPRESS_ACTIVE_PLUGINS, null );
	if ( is_null( $plugins ) ) {
		defined( 'SECUPRESS_ACTIVE_PLUGINS_ERROR' ) || define( 'SECUPRESS_ACTIVE_PLUGINS_ERROR', true );
		return $pre;
	}
	return $plugins;
}

/**
 * @see secupress_get_not_installed_plugins_list()
 *
 * @since 2.2.6
 * @author Julio Potier
 * @return (array) $plugins
 **/
function _secupress_get_not_installed_plugins_list_all() {
	$ins_plugins = get_site_option( SECUPRESS_INSTALLED_PLUGINS );
	if ( ! $ins_plugins ) {
		return [];
	}
	if ( ! function_exists( 'get_plugins' ) ) {
		include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
	}
	$get_plugins = get_plugins();
	$plugins     = array_diff_key( $get_plugins, $ins_plugins );

	return $plugins;
}

$__plugins_del_me  = [];
$__plugins         = [];
$__plugins['old']  = get_site_option( SECUPRESS_INSTALLED_MUPLUGINS, [] );
$__plugins['real'] = [];
foreach ( wp_get_mu_plugins() as $mu ) {
	$__plugins['real'][ basename( $mu ) ] = 1;
}
$__plugins['more'] = array_diff_key( $__plugins['real'], $__plugins['old'] );
$__plugins['less'] = array_diff_key( $__plugins['old'], $__plugins['real'] );
if ( ! empty( $__plugins['more'] ) ) {
	foreach( $__plugins['more'] as $mufile => $dummy ) {
		$key = str_replace( '.', '', microtime( true ) );
		rename( WPMU_PLUGIN_DIR . '/' . $mufile, WPMU_PLUGIN_DIR . '/' . $mufile . '_' . $key );
		file_put_contents( WPMU_PLUGIN_DIR . '/' . $mufile, '' ); // Recreate the same fiename with empty content or WP will trigger a 'include_once warning' error.
		$__plugins_del_me[] = WPMU_PLUGIN_DIR . '/' . $mufile;
		usleep( mt_rand( 10, 100 ) );
	}
}
if ( ! empty( $__plugins['less'] ) ) {
	$__plugins['old'] = array_diff_key( $__plugins['old'], $__plugins['less'] );
	update_option( SECUPRESS_INSTALLED_MUPLUGINS, $__plugins['old'] );
}

$__plugins['active'] = get_option( 'active_plugins' );
$__plugins['all']    = array_keys( _secupress_get_not_installed_plugins_list_all() );
$__plugins           = array_diff( $__plugins['active'], $__plugins['all'] );
if ( $__plugins ) {
	update_option( 'active_plugins', $__plugins );
}

unset( $__plugins, $mufile, $dummy );

add_action( 'muplugins_loaded', function() use( $__plugins_del_me ) {
	array_map( function( $file ) {
	    @unlink( $file );
	}, $__plugins_del_me );
	unset( $__plugins_del_me );
} );