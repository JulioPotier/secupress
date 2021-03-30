<?php
/**
 * Module Name: Correct Debug Settings
 * Description: Set the constants <code>WP_DEBUG</code> & <code>WP_DEBUG_DISPLAY</code> from the <code>wp-config.php</code> file to <code>false</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_debugging_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_debugging_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_debugging_activation() {
	secupress_wpconfig_modules_activation( 'debugging' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_debugging_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_debugging_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_debugging_deactivation() {
	secupress_wpconfig_modules_deactivation( 'debugging' );
}
