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

	require_once( SECUPRESS_MODULES_PATH . 'logs/plugins/inc/php/action-logs/class-secupress-logs.php' );

	SecuPress_Logs::get_instance();

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
add_action( 'secupress_deactivate_plugin_action-logs', array( 'SecuPress_Logs', 'delete_logs' ) );
