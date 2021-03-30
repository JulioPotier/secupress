<?php
/**
 * Module Name: Disallow Database Repair Page
 * Description: Set the constant <code>WP_ALLOW_REPAIR</code> from the <code>wp-config.php</code> file to <code>false</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_repair_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_repair_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_repair_activation() {
	secupress_wpconfig_modules_activation( 'repair' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_repair_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_repair_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_repair_deactivation() {
	secupress_wpconfig_modules_deactivation( 'repair' );
}

add_action( 'plugins_loaded', 'secupress_prevent_allow_repair_page' );
function secupress_prevent_allow_repair_page() {
	if ( defined( 'WP_REPAIRING' ) && WP_REPAIRING ) {
		secupress_die( '<h1>' . __( 'Something went wrong.', 'secupress' ) . '</h1>', '', [ 'force_die' => true ] );
	}
}
