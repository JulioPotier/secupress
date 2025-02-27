<?php
/**
 * Module Name: Skip Core Bundles
 * Description: Set the constant <code>CORE_UPGRADE_SKIP_NEW_BUNDLED</code> from the <code>wp-config.php</code> file to <code>true</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_skip_bundle_activation' );
add_action( 'secupress.plugins.activation', 'secupress_skip_bundle_activation' );
/**
 * On module activation, remove the define.
 *
 * @author Julio Potier
 * @since 2.2.6
 */
function secupress_skip_bundle_activation() {
	secupress_wpconfig_modules_activation( 'skip_bundle' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_skip_bundle_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_skip_bundle_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @author Julio Potier
 * @since 2.2.6
 */
function secupress_skip_bundle_deactivation() {
	secupress_wpconfig_modules_deactivation( 'skip_bundle' );
}
