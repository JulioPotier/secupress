<?php
/**
 * Module Name: Minor Updates
 * Description: Allow Auto Updates for Minor Versions
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.plugins.activation', 'secupress_minor_updates_activation' );
/**
 * On module activation, comment the defines.
 *
 * @since 1.2.3
 * @author Grégory Viguier
 */
function secupress_minor_updates_activation() {
	// Comment the 2 constants if they are defined.
	$filepath  = secupress_is_wpconfig_writable();
	$failed    = array();
	$constants = array(
		'DISALLOW_FILE_MODS'         => true,
		'AUTOMATIC_UPDATER_DISABLED' => true,
		'WP_AUTO_UPDATE_CORE'        => false,
	);

	foreach ( $constants as $constant => $val ) {
		if ( ! defined( $constant ) || (bool) constant( $constant ) !== $val ) {
			continue;
		}

		if ( $filepath ) {
			$success = secupress_comment_constant( $constant, $filepath );
		} else {
			$success = false;
		}

		if ( ! $success ) {
			$val      = var_export( $val, true );
			$failed[] = "define( '$constant', $val );";
		}
	}

	if ( ! $failed ) {
		// OK: not defined or successfully commented.
		return;
	}

	$count  = count( $failed );
	$failed = implode( "\n", $failed );

	if ( ! $filepath ) {
		$message = sprintf(
			/** Translators: 1 is a file name, 2 is some code. */
			__( 'The %1$s file is not writable. Please remove the following code from the file: %2$s', 'secupress' ),
			'<code>' . secupress_get_wpconfig_filename() . '</code>',
			"<pre>$failed</pre>"
		);
		secupress_add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
	} else {
		$message = sprintf(
			/** Translators: 1 is the plugin name, 2 is a file name, 3 is some code. */
			_n( '%1$s couldn’t remove a constant definition from the %2$s file. Please remove the following line from the file: %3$s', '%1$s couldn’t remove some constant definitions from the %2$s file. Please remove the following lines from the file: %3$s', $count, 'secupress' ),
			SECUPRESS_PLUGIN_NAME,
			'<code>' . secupress_get_wpconfig_filename() . '</code>',
			"<pre>$failed</pre>"
		);
		secupress_add_settings_error( 'general', 'constant_not_commented', $message, 'error' );
	}
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_minor_updates_activate_file' );
/**
 * On module deactivation, maybe put the constants back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_minor_updates_activate_file() {
	secupress_minor_updates_activation();
	secupress_scanit_async( 'Auto_Update', 3 );
}


add_action( 'secupress.plugins.deactivation', 'secupress_minor_updates_deactivation' );
/**
 * On module deactivation, maybe put the constants back.
 *
 * @since 1.2.3
 * @author Grégory Viguier
 */
function secupress_minor_updates_deactivation() {
	// Uncomment the 2 constants.
	$filepath  = secupress_is_wpconfig_writable();
	$constants = array(
		'DISALLOW_FILE_MODS',
		'AUTOMATIC_UPDATER_DISABLED',
		'WP_AUTO_UPDATE_CORE',
	);

	if ( $filepath ) {
		foreach ( $constants as $constant ) {
			secupress_uncomment_constant( $constant, $filepath );
		}
	}
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_minor_updates_deactivate_file' );
/**
 * On module deactivation, maybe put the constants back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_minor_updates_deactivate_file() {
	secupress_minor_updates_deactivation();
	secupress_scanit_async( 'Auto_Update', 3 );
}


/** --------------------------------------------------------------------------------------------- */
/** USE FILTERS ================================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'automatic_updater_disabled',    '__return_false', PHP_INT_MAX );
add_filter( 'allow_minor_auto_core_updates', '__return_true',  PHP_INT_MAX );
