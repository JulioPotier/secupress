<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * On wpconfig modules activation
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_modules_activation( $marker, $force_rewrite = false ) {

	$constants         = secupress_get_constants_from_marker( $marker );
	$wpconfig_filepath = secupress_is_wpconfig_writable();
	$wpconfig_filename = secupress_get_wpconfig_filename();
	if ( ! $wpconfig_filepath ) {
		$message = sprintf( __( 'The %1$s file is not writable. Please apply %2$s rights on this file.', 'secupress' ), secupress_code_me( $wpconfig_filename ), secupress_code_me( '0644' ) );
		secupress_add_settings_error( 'general', 'wp_config_not_writable', $message, 'error' );
		return;
	}

	$new_define = [];
	$error      = [];
	$const_err  = [];
	foreach ( $constants as $constant => $correct_value ) {
		if ( 0 === strpos( $correct_value, '0' ) ) { // octal (fs_chmod)
			$check = defined( $constant ) ? '0' . decoct( constant( $constant ) ) : null;
		} else {
			$check = defined( $constant ) ? constant( $constant ) : null;
		}
		if ( $correct_value !== $check || $force_rewrite ) {
			// This will be printed in the wp-config file.
			if ( is_bool( $correct_value ) ) {
				$new_define[] = sprintf( "define( '%s', %s );", $constant, var_export( $correct_value, true ) );
			} elseif ( is_integer( $correct_value ) || 0 === strpos( $correct_value, '0' ) ) {
				$new_define[] = "define( '$constant', " . $correct_value . " );";
			} else {
				$new_define[] = "define( '$constant', '" . $correct_value . "' );";
			}
			if ( $force_rewrite ) {
				continue;
			}
			// Remove the constant we could have previously set, and comment old value.
			$replaced = secupress_comment_constant( $constant, $wpconfig_filepath, $marker );
			if ( ! $replaced ) {
				$const_err[] = $constant;
				// The constant couldn't be removed or commented: display an error message.
				if ( is_bool( $check ) ) {
					$error[] = sprintf( "define( '%s', %s );", $constant, var_export( $check, true ) );
				} elseif ( is_integer( $check ) || 0 === strpos( $check, '0' ) ) {
					$error[] = "define( '$constant', " . $check . " );";
				} else { // string.
					$error[] = "define( '$constant', '" . $check . "' );";
				}
			}
		}
	}

	if ( ! empty( $error ) ) {
		$messages  = '';
		foreach( $error as $i => $err ) {
			$messages .= sprintf(
				/** Translators: 1 is a constant name, 2 is a file name, 4 and 5 are a small parts of code. */
				__( 'Cannot change the value of the constant %1$s in the %2$s file. Please edit it and replace the lines that states: %3$s by: %4$s', 'secupress' ),
				secupress_code_me( $const_err[ $i ] ),
				secupress_code_me( $wpconfig_filename ),
				secupress_code_me( $err ),
				secupress_tag_me( $new_define[ $i ], 'pre' )
			);
		}
		secupress_add_settings_error( 'general', 'constant_not_removed', $messages, 'error' );
		// return false; // Do not return here, we can still ad the other constants.
	}
	// Add our constant now.
	if ( ! empty( $new_define ) ) {
		$args  = [ 'marker' => $marker, 'put' => 'append', 'text' => '<?php' ];

		if ( ! secupress_put_contents( $wpconfig_filepath, implode( "\n", $new_define ), $args ) ) {
			// The constant couldn't be added: display an error message.
			$message = sprintf(
				/** Translators: 1 is a file name, 2 is a small part of code. */
				__( 'Cannot add the constants to the %1$s file. Please edit it and add the following at the beginning: %2$s', 'secupress' ),
				secupress_code_me( $wpconfig_filename ),
				"<pre># BEGIN SecuPress $marker\n" . implode( "\n", $new_define ) . "\n# END SecuPress</pre>"
			);
			secupress_add_settings_error( 'general', 'constant_not_added', $message, 'error' );
			return false;
		}
	}
	return true;
}


/**
 * On module deactivation, maybe set the constant back.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_wpconfig_modules_deactivation( $marker ) {
	$constants = secupress_get_constants_from_marker( $marker );
	if ( ! $constants ) {
		wp_die( 'Missing or incorrect marker' ); // Do not translate.
	}

	$wpconfig_filepath = secupress_is_wpconfig_writable();
	$wpconfig_filename = secupress_get_wpconfig_filename();

	foreach ( $constants as $constant => $correct_value ) {
		secupress_uncomment_constant( $constant, $wpconfig_filepath );
	}
	if ( ! defined( 'SECUPRESS_NO_SANDBOX' ) ) {
		define( 'SECUPRESS_NO_SANDBOX', true );
	}
	if ( ! secupress_comment_constant( 'secupress_dummy_foobar', $wpconfig_filepath, $marker ) ) {
		$new_define = [];
		foreach ( $constants as $constant => $correct_value ) {
			if ( is_bool( $correct_value ) ) {
				$new_define[] = sprintf( "define( '%s', %s );", $constant, var_export( $correct_value, true ) );
			} elseif ( is_integer( $correct_value ) || 0 === strpos( $correct_value, '0' ) ) {
				$new_define[] = "define( '$constant', " . $correct_value . " );";
			} else {
				$new_define[] = "define( '$constant', '" . $correct_value . "' );";
			}
		}
		$message = sprintf(
			/** Translators: 1 is a constant name, 2 is a file name, 3 is a small part of code. */
			__( 'Cannot remove the constant %1$s from the %2$s file. Please edit it and remove the following lines: %3$s', 'secupress' ),
			'<code>' . implode( '</code>, <code>', array_keys( $constants ) ) . '</code>',
			"<code>$wpconfig_filename</code>",
			"<pre># BEGIN SecuPress $marker\n" . implode( "\n", $new_define ) . "\n# END SecuPress</pre>"
		);
		secupress_add_settings_error( 'general', 'constant_not_removed', $message, 'error' );
		return;
	}
}


/**
 * Return correct constants and their value for a designated marker
 *
 * @since 2.2.1 add "remove_all_filters"
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $marker A marker for wp-config
 * @return (array) Array of strings that are constant names
 **/
function secupress_get_constants_from_marker( $marker ) {
	switch ( $marker ) {
		case 'adminemail':
			if ( ! function_exists( '__get_option' ) ) {
				require( ABSPATH . 'wp-admin/includes/upgrade.php' );
			}
			return [ 'SECUPRESS_LOCKED_ADMIN_EMAIL' => __get_option( 'admin_email' ) ];
		break;

		case 'debugging':
			return [ 'WP_DEBUG' => false, 'WP_DEBUG_DISPLAY' => false ];
		break;

		case 'dieondberror':
			return [ 'DIEONDBERROR' => false ];
		break;

		case 'file_edit':
			return [ 'DISALLOW_FILE_EDIT' => true ];
		break;

		case 'script_concat':
			return [ 'CONCATENATE_SCRIPTS' => false ];
		break;

		case 'locations':
			remove_all_filters( 'pre_option_siteurl' );
			remove_all_filters( 'option_siteurl' );
			remove_all_filters( 'site_url' );
			remove_all_filters( 'pre_option_home' );
			remove_all_filters( 'option_home' );
			remove_all_filters( 'home_url' );
			return [    'RELOCATE'   => false, 
						'WP_SITEURL' => get_option( 'siteurl' ), 
						'WP_HOME'    => get_option( 'home' )
					];
		break;

		case 'force_https':
			return [ 'FORCE_SSL_ADMIN' => true, 'FORCE_SSL_LOGIN' => true ];
		break;

		case 'repair':
			return [ 'WP_ALLOW_REPAIR' => false ];
		break;

		case 'unfiltered_uploads':
			return [ 'ALLOW_UNFILTERED_UPLOADS' => false ];
		break;

		case 'skip_bundle':
			return [ 'CORE_UPGRADE_SKIP_NEW_BUNDLED' => true ];
		break;

		default:
			wp_die( 'Missing or incorrect marker: ' . esc_html( $marker ) ); // Do not translate.
		break;
	}
}


/**
 * Returns a small explanation on what will be done in wp-config
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $constant Constant Name
 * @param (string) $value Constant Value
 * @return (string) Translated text
 **/
function secupress_get_wpconfig_constant_text( $constant, $value ) {
	return sprintf( __( 'The constant <code>%s</code> will be set on <code>%s</code>.', 'secupress' ), esc_html( $constant ), esc_html( $value ) );
}


/**
 * Returns a small error on what will be done in wp-config
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $constant Constant Name
 * @param (string) $value Constant Value
 * @return (string) Translated text
 **/
function secupress_get_wpconfig_constant_error( $constant, $value ) {
	return sprintf( __( 'The constant <code>%1$s</code> should be set on <code>%2$s</code>.<br>Please deactivate and activate this module again.', 'secupress' ), $constant, $value );
}

add_filter( 'secupress.settings.section.submit_button_args', 'secupress_change_submit_button_label_for_db_prefix', 10, 2 );
/**
 * Change the submit button label for change db prefix setting
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (array) $args
 * @param (string) $section Module section
 * @return (array)
 **/
function secupress_change_submit_button_label_for_db_prefix( $args, $section ) {
	if ( 'database' === $section ) {
		$args['label'] = __( 'Change prefix', 'secupress' );
	}
	return $args;
}
