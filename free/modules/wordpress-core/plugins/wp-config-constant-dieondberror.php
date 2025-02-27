<?php
/**
 * Module Name: Hide Database Errors
 * Description: Set the constant <code>DIEONDBERROR</code> from the <code>wp-config.php</code> file to <code>false</code> and creates a <code>db-error.php</code> file in wp-content folder.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.2.6
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
 * @since 2.2.6 Creates the db-error.php file
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_dieondberror_activation() {
	secupress_wpconfig_modules_activation( 'dieondberror' );
	
	$filesystem = secupress_get_filesystem();
	$filename   = 'db-error';

	$args = array(
		'{{PLUGIN_NAME}}' => SECUPRESS_PLUGIN_NAME,
	);

	$contents = $filesystem->get_contents( SECUPRESS_INC_PATH . 'data/db-error.phps' );
	$contents = str_replace( array_keys( $args ), $args, $contents );

	secupress_create_dropin_plugin( $filename, $contents );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wpconfig_dieondberror_deactivation' );
add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_dieondberror_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.2.6 Deletes the db-error.php file
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_dieondberror_deactivation() {
	secupress_wpconfig_modules_deactivation( 'dieondberror' );
	$filename   = WP_CONTENT_DIR . '/db-error.php';
	$content    = file_get_contents( $filename );
	// Delete it only if it belongs to us!
	if ( false !== strpos( $content, 'SecuPress' ) ) {
		secupress_delete_dropin_plugin( $filename );
	}
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
