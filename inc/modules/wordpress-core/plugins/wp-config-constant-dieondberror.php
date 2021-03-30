<?php
/**
 * Module Name: Hide Database Errors
 * Description: Set the constant <code>DIEONDBERROR</code> from the <code>wp-config.php</code> file to <code>false</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_dieondberror_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_dieondberror_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_dieondberror_activation() {
	secupress_wpconfig_modules_activation( 'dieondberror' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_dieondberror_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_dieondberror_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_dieondberror_deactivation() {
	secupress_wpconfig_modules_deactivation( 'dieondberror' );
}

add_action( 'wp', 'secupress_force_hide_db_errors' );
/**
 * Force hide db error
 *
 * @since 2.0
 * @author Julio Potier
 *
 **/
function secupress_force_hide_db_errors() {
	global $wpdb;
	$wpdb->hide_errors();
}
