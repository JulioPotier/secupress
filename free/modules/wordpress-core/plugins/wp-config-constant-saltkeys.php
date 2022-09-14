<?php
/**
 * Module Name: Correct Security Keys
 * Description: Creates a mu-plugin with 8 constants.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_saltkeys_activation' );
add_action( 'secupress.plugins.activation', 'secupress_wpconfig_saltkeys_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_saltkeys_activation() {
	// Don't do it in the submodule file to prevent 8 db delete query at each load for nothing mainly.
	// So we just do it on activation, mu file present or not.
	secupress_delete_db_salt_keys();

	if ( defined( 'SECUPRESS_SALT_KEYS_MODULE_EXISTS' ) ) {
		return;
	}

	$current_user = wp_get_current_user();
	secupress_set_site_transient( 'secupress-add-salt-muplugin', array( 'ID' => $current_user->ID ) );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_saltkeys_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_saltkeys_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_saltkeys_deactivation() {
    $current_user = wp_get_current_user();
    secupress_set_site_transient( 'secupress-auto-login', array( 'ID' => $current_user->ID ) );
	// $mu = reset( secupress_find_muplugin( '_secupress_salt_keys_' ) );
	// secupress_remove_old_plugin_file( $mu );
}
