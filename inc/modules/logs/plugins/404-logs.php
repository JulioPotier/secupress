<?php
/*
Module Name: 404 Logs
Description: Logs "404 Page Not Found" errors on the site.
Main Module: logs
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* INCLUDE AND INITIATE ========================================================================= */
/*------------------------------------------------------------------------------------------------*/

if ( ! did_action( 'secupress_plugins_loaded' ) ) {

	if ( ! class_exists( 'SecuPress_Logs' ) ) {
		secupress_require_class( 'Logs' );
	}

	require_once( SECUPRESS_MODULES_PATH . 'logs/plugins/inc/php/404-logs/class-secupress-404-logs.php' );

	SecuPress_404_Logs::get_instance();

}


/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Delete logs on deactivation.
 *
 * @since 1.0
 *
 * @param (array) $args Some parameters.
 */
add_action( 'secupress_deactivate_plugin_404-logs', 'secupress_deactivate_plugin_404_logs' );

function secupress_deactivate_plugin_404_logs() {
	if ( class_exists( 'SecuPress_404_Logs' ) ) {
		SecuPress_404_Logs::get_instance()->delete_logs();
	}
}
