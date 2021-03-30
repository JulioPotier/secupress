<?php
/**
 * Module Name: Disallow Unfiltered Uploads
 * Description: Remove the constant <code>ALLOW_UNFILTERED_UPLOADS</code> from the <code>wp-config.php</code> file.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_unfiltered_uploads_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_unfiltered_uploads_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_unfiltered_uploads_activation() {
	secupress_wpconfig_modules_activation( 'unfiltered_uploads' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_unfiltered_uploads_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_unfiltered_uploads_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_unfiltered_uploads_deactivation() {
	secupress_wpconfig_modules_deactivation( 'unfiltered_uploads' );
}
