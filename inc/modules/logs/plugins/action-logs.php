<?php
/**
 * Module Name: Actions Logs
 * Description: Logs important events on the site, like some critical option changes and some hooks.
 * Main Module: logs
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** INCLUDE AND INITIATE ======================================================================== */
/** --------------------------------------------------------------------------------------------- */

if ( ! did_action( 'secupress.plugins.loaded' ) ) {

	if ( ! class_exists( 'SecuPress_Logs' ) ) {
		secupress_require_class( 'Logs' );
	}

	require_once( SECUPRESS_MODULES_PATH . 'logs/plugins/inc/php/action-logs/class-secupress-action-logs.php' );

	SecuPress_Action_Logs::get_instance();
}


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_deactivate_plugin_action_logs' );
add_action( 'secupress.plugins.deactivation',                                         'secupress_deactivate_plugin_action_logs' );
/**
 * Delete logs on deactivation.
 *
 * @since 1.0
 */
function secupress_deactivate_plugin_action_logs() {
	if ( class_exists( 'SecuPress_Action_Logs' ) ) {
		SecuPress_Action_Logs::get_instance()->delete_logs();
	}
}
