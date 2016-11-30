<?php
/**
 * Module Name: Disallow Unfiltered Uploads
 * Description: Remove the constant <code>ALLOW_UNFILTERED_UPLOADS</code> from the <code>wp-config.php</code> file.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 1.0
 */
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_unfiltered_uploads_activation' );
add_action( 'secupress.plugins.activation', 'secupress_unfiltered_uploads_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 */
function secupress_unfiltered_uploads_activation() {
	$constant = 'ALLOW_UNFILTERED_UPLOADS';
	$check    = defined( $constant ) ? constant( $constant ) : false;

	if ( ! $check ) {
		// OK, not defined or false.
		return;
	}

	$wpconfig_filepath = secupress_find_wpconfig_path();
	$is_writable       = $wpconfig_filepath && wp_is_writable( $wpconfig_filepath );

	if ( ! $is_writable ) {
		/** Translators: 1 is a file name, 2 is a code. */
		$message = sprintf( __( 'The %1$s file is not writable. Please apply %2$s write rights to the file.', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' );
		add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
		return;
	}

	// Comment old value.
	$replaced = secupress_replace_content( $wpconfig_filepath, "@^define\s*\(\s*('$constant'|\"$constant\"),(.*);\s*$@mU", '/*Commented by SecuPress*/ /* $0 */' );

	if ( $replaced ) {
		// OK, we succeeded to comment the constant.
		return;
	}

	// Not fixed, we failed to comment the constant: display an error message.
	if ( true === $check ) {
		$value = 'true';
	} elseif ( is_int( $check ) ) {
		$value = $check;
	} else {
		$value = "'$check'";
	}
	$message = sprintf(
		/** Translators: 1 is the plugin name, 2 is a constant name, 3 is a file name, 4 is a small part of code. */
		__( '%1$s couldn\'t remove the constant %2$s from the %3$s file. Please edit the file and remove the line that states: %4$s.', 'secupress' ),
		SECUPRESS_PLUGIN_NAME,
		"<code>$constant</code>",
		'<code>wp-config.php</code>',
		"<code>define( '$constant', $value );</code>"
	);
	add_settings_error( 'general', 'constant_not_removed', $message, 'error' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_unfiltered_uploads_deactivate' );
add_action( 'secupress.plugins.deactivation', 'secupress_unfiltered_uploads_deactivate' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 */
function secupress_unfiltered_uploads_deactivate() {
	$constant          = 'ALLOW_UNFILTERED_UPLOADS';
	$wpconfig_filepath = secupress_find_wpconfig_path();
	$is_writable       = $wpconfig_filepath && wp_is_writable( $wpconfig_filepath );

	if ( ! $is_writable ) {
		/** Translators: 1 is a file name, 2 is a code. */
		$message = sprintf( __( 'The %1$s file is not writable. Please apply %2$s write rights to the file.', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' );
		add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
		return;
	}

	// Remove the comments.
	secupress_replace_content( $wpconfig_filepath, "@/\*Commented by SecuPress\*/ /\* *(define\s*\(\s*('$constant'|\"$constant\"),(.*);) *\*/@", '$1' );
}
