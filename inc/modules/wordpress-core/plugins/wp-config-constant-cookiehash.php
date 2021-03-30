<?php
/**
 * Module Name: Correct Cookie Default Name Value
 * Description: Add a mu-plugin to generate a custom <code>COOKIEHASH</code> name value.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_cookiehash_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_cookiehash_activation' );
/**
 * On module activation, change the COOKIEHASH value if not already set.
 * If you need to change it, you can just change the SP hash or delete this file.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_cookiehash_activation() {
	if ( defined( 'SECUPRESS_COOKIEHASH_MODULE_EXISTS' ) ) {
		return;
	}

	$current_user = wp_get_current_user();
	secupress_set_site_transient( 'secupress-add-cookiehash-muplugin', array( 'ID' => $current_user->ID, 'username' => $current_user->user_login ) );
}



add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_cookiehash_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_cookiehash_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_cookiehash_deactivation() {
	// $mu = secupress_find_muplugin( '_secupress_cookiehash_' );
	// secupress_remove_old_plugin_file( reset( $mu ) );
}
