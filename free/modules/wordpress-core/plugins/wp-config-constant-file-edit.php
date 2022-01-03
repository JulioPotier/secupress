<?php
/**
 * Module Name: Disallow File Edition
 * Description: Set the constant <code>DISALLOW_FILE_EDIT</code> from the <code>wp-config.php</code> file to <code>true</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_disallow_file_edit_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_disallow_file_edit_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_disallow_file_edit_activation() {
	secupress_wpconfig_modules_activation( 'file_edit' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_disallow_file_edit_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_disallow_file_edit_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_disallow_file_edit_deactivation() {
	secupress_wpconfig_modules_deactivation( 'file_edit' );
}
