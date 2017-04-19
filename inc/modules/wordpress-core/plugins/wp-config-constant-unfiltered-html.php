<?php
/**
 * Module Name: Disallow Unfiltered HTML
 * Description: Set the constant <code>DISALLOW_UNFILTERED_HTML</code> from the <code>wp-config.php</code> file to <code>true</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_unfiltered_html_activation' );
add_action( 'secupress.plugins.activation', 'secupress_unfiltered_html_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 */
function secupress_unfiltered_html_activation() {
	$constant = 'DISALLOW_UNFILTERED_HTML';
	$marker   = 'unfiltered_html';
	$check    = defined( $constant ) ? constant( $constant ) : false;

	if ( $check ) {
		// OK, defined to true.
		return;
	}

	$new_define        = "define( '$constant', true );";
	$wpconfig_filepath = secupress_is_wpconfig_writable();

	if ( ! $wpconfig_filepath ) {
		/** Translators: 1 is a file name, 2 is a code. */
		$message = sprintf( __( 'The %1$s file is not writable. Please apply %2$s write rights to the file.', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' );
		secupress_add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
		return;
	}

	if ( defined( $constant ) ) {
		// Remove the constant we could have previously set, and comment old value.
		$replaced = secupress_comment_constant( $constant, $wpconfig_filepath, $marker );

		if ( ! $replaced ) {
			// The constant couldn't be removed or commented: display an error message.
			if ( true === $check ) {
				$value = 'true';
			} elseif ( is_int( $check ) ) {
				$value = $check;
			} else {
				$value = "'$check'";
			}
			$message = sprintf(
				/** Translators: 1 is the plugin name, 2 is a constant name, 3 is a file name, 4 and 5 are a small parts of code. */
				__( '%1$s couldn\'t change the value of the constant %2$s in the %3$s file. Please edit the file and replace the line that states: %4$s by: %5$s', 'secupress' ),
				SECUPRESS_PLUGIN_NAME,
				"<code>$constant</code>",
				'<code>wp-config.php</code>',
				"<code>define( '$constant', $value );</code>",
				"<pre># BEGIN SecuPress $marker\n$new_define\n# END SecuPress</pre>"
			);
			secupress_add_settings_error( 'general', 'constant_not_removed', $message, 'error' );
			return;
		}
	}

	// Add our constant now.
	$added = secupress_put_contents( $wpconfig_filepath, $new_define, array( 'marker' => $marker, 'put' => 'append', 'text' => '<?php' ) );

	if ( $added ) {
		// OK, we succeeded to add our constant.
		return;
	}

	// The constant couldn't be added: display an error message.
	$message = sprintf(
		/** Translators: 1 is the plugin name, 2 is a constant name, 3 is a file name, 4 is a small part of code. */
		__( '%1$s couldn\'t add the constant %2$s to the %3$s file. Please edit the file and add the following at the beginning of it: %4$s.', 'secupress' ),
		SECUPRESS_PLUGIN_NAME,
		"<code>$constant</code>",
		'<code>wp-config.php</code>',
		"<pre># BEGIN SecuPress $marker\n$new_define\n# END SecuPress</pre>"
	);
	secupress_add_settings_error( 'general', 'constant_not_added', $message, 'error' );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_unfiltered_html_deactivate' );
add_action( 'secupress.plugins.deactivation', 'secupress_unfiltered_html_deactivate' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 */
function secupress_unfiltered_html_deactivate() {
	$constant          = 'DISALLOW_UNFILTERED_HTML';
	$marker            = 'unfiltered_html';
	$wpconfig_filepath = secupress_is_wpconfig_writable();

	if ( ! $wpconfig_filepath ) {
		/** Translators: 1 is a file name, 2 is a code. */
		$message = sprintf( __( 'The %1$s file is not writable. Please apply %2$s write rights to the file.', 'secupress' ), '<code>wp-config.php</code>', '<code>0644</code>' );
		secupress_add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
		return;
	}

	// Remove the constant we could have previously set, and uncomment the original constant definition.
	secupress_uncomment_constant( $constant, $wpconfig_filepath, $marker );
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER FILTERS =============================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'wp_kses_allowed_html', 'secupress_unfiltered_html_allowed_tags', PHP_INT_MAX );
/**
 * Make sure the `<iframe>` and `<script>` tags are not added to the list of allowed tags, whatever the context is.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (array) $tags An array of allowed tags + their attributes.
 *
 * @return (array)
 */
function secupress_unfiltered_html_allowed_tags( $tags ) {
	if ( is_array( $tags ) ) {
		unset( $tags['iframe'], $tags['script'] );
	}
	return $tags;
}
