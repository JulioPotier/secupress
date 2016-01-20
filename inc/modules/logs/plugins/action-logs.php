<?php
/*
Module Name: Actions Logs
Description: Logs important events on the site, like some critical option changes and some hooks.
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

	require_once( SECUPRESS_MODULES_PATH . 'logs/plugins/inc/php/action-logs/class-secupress-action-logs.php' );

	SecuPress_Action_Logs::get_instance();

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
add_action( 'secupress_deactivate_plugin_action-logs', 'secupress_deactivate_plugin_action_logs' );

function secupress_deactivate_plugin_action_logs() {
	if ( class_exists( 'SecuPress_Action_Logs' ) ) {
		SecuPress_Action_Logs::get_instance()->delete_logs();
	}
}
