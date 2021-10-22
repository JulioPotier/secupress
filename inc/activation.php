<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATE ==================================================================================== */
/** --------------------------------------------------------------------------------------------- */

register_activation_hook( SECUPRESS_FILE, 'secupress_activation' );
/**
 * Tell WP what to do when the plugin is activated.
 *
 * @since 1.0
 */
function secupress_activation() {
	// Make sure we have our toys.
	secupress_load_functions();

	/**
	 * Fires on SecuPress activation.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.activation' );

	/**
	 * As this activation hook appens before our sub-modules are loaded (and the page is reloaded right after that),
	 * this transient will trigger a custom activation hook in `secupress_load_plugins()`.
	 */
	set_site_transient( 'secupress_activation', 1 );
}


add_action( 'secupress.plugins.activation', 'secupress_maybe_set_rules_on_activation', 10000 );
/**
 * Maybe set rules to add in `.htaccess` or `web.config` file on SecuPress activation.
 *
 * @since 1.0
 */
function secupress_maybe_set_rules_on_activation() {
	global $is_apache, $is_iis7, $is_nginx;

	if ( ! $is_apache && ! $is_iis7 && ! $is_nginx ) {
		// System not supported.
		return;
	}

	$rules = array();

	/**
	 * Rules that must be added to the `.htaccess`, `web.config`, or `nginx.conf` file on SecuPress activation.
	 *
	 * @since 1.0
	 *
	 * @param (array) $rules An array of rules with the modules marker as key and rules (string) as value. For IIS7 it's an array of arguments (each one containing a row with the rules).
	 */
	$rules = apply_filters( 'secupress.plugins.activation.write_rules', $rules );

	if ( $rules ) {
		// We store the rules, they will be merged and written in `secupress_maybe_write_rules_on_activation()`.
		secupress_cache_data( 'plugins-activation-write_rules', $rules );
	}
}


add_action( 'secupress.all.plugins.activation', 'secupress_maybe_write_rules_on_activation', 10000 );
/**
 * Maybe add rules in `.htaccess` or `web.config` file on SecuPress or SecuPress Pro activation.
 *
 * @since 1.1.4
 */
function secupress_maybe_write_rules_on_activation() {
	global $is_apache, $is_iis7, $is_nginx;

	if ( ! $is_apache && ! $is_iis7 && ! $is_nginx ) {
		// System not supported.
		return;
	}

	$rules = secupress_cache_data( 'plugins-activation-write_rules' );
	secupress_cache_data( 'plugins-activation-write_rules', null );

	secupress_write_rules_on_activation( $rules );
}


/**
 * Add rules in `.htaccess` or `web.config` file on plugin activation.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (array) $rules An array of rules to write.
 */
function secupress_write_rules_on_activation( $rules ) {
	global $is_apache, $is_iis7;

	$rules = $rules && is_array( $rules ) ? array_filter( $rules ) : false;

	if ( ! $rules ) {
		// Meh.
		return;
	}

	// Apache.
	if ( $is_apache ) {
		$filesystem   = secupress_get_filesystem();
		$home_path    = secupress_get_home_path();
		$file_path    = $home_path . '.htaccess';
		$file_content = '';
		$new_content  = '';

		// Get the whole content of the file.
		if ( $filesystem->exists( $file_path ) && $filesystem->is_writable( $file_path ) ) {
			$file_content = (string) $filesystem->get_contents( $file_path );
			/**
			 * Filter the `.htaccess` file content before add new rules.
			 *
			 * @since 1.0
			 *
			 * @param (string) $file_content The file content.
			 */
			$file_content = apply_filters( 'secupress.plugins.activation.htaccess_content_before_write_rules', $file_content );
		}

		foreach ( $rules as $marker => $new_rules ) {
			// Remove old content (shouldn't left anything).
			if ( $file_content ) {
				$pattern      = '/# BEGIN SecuPress ' . $marker . '(.*)# END SecuPress\s*?/isU';
				$file_content = preg_replace( $pattern, '', $file_content );
			}
			// Create new content.
			$new_content .= '# BEGIN SecuPress ' . $marker . PHP_EOL;
			$new_content .= trim( $new_rules ) . PHP_EOL;
			$new_content .= '# END SecuPress' . PHP_EOL . PHP_EOL;
		}

		if ( ! secupress_root_file_is_writable( '.htaccess' ) ) {
			/** Translators: 1 is a file name, 2 is some code. */
			$message = sprintf( __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ), '<code>.htaccess</code>', '<pre>' . esc_html( $new_content ) . '</pre>' );
			secupress_add_notice( $message, 'error', 'secupress-activation-file-not-writable' );
			return;
		}

		$file_content = $new_content . $file_content;

		// Save the file.
		$filesystem->put_contents( $file_path, $file_content, FS_CHMOD_FILE );
		return;
	}

	// IIS7.
	if ( $is_iis7 ) {
		$filesystem = secupress_get_filesystem();
		$home_path  = secupress_get_home_path();
		$file_path  = $home_path . 'web.config';

		// If configuration file does not exist then we create one.
		if ( ! $filesystem->exists( $file_path ) ) {
			$filesystem->put_contents( $file_path, '<configuration/>' );
		}

		$doc = new DOMDocument();
		$doc->preserveWhiteSpace = false;

		// Load the file.
		$loaded = false;
		if ( false !== $doc->load( $file_path ) ) {
			$loaded = true;
		}

		// Now, if the file failed to load, we'll only store data in an array and display it in a message for the user.
		if ( $loaded ) {
			$xpath = new DOMXPath( $doc );
		} else {
			$data = array();
		}

		foreach ( $rules as $marker => $args ) {
			$args = wp_parse_args( $args, array(
				'nodes_string' => '',
				'node_types'   => false,
				'path'         => '',
				'attribute'    => 'name',
			) );

			$nodes_string = $args['nodes_string'];
			$nodes_string = is_array( $nodes_string ) ? implode( "\n", $nodes_string ) : $nodes_string;
			$nodes_string = trim( $nodes_string, "\r\n\t " );
			$node_types   = $args['node_types'];
			$path         = $args['path'];
			$attribute    = $args['attribute'];

			$path_end = ! $path && strpos( ltrim( $nodes_string ), '<rule ' ) === 0 ? '/rewrite/rules/rule' : '';
			$path     = '/configuration/system.webServer' . ( $path ? '/' . trim( $path, '/' ) : '' ) . $path_end;

			if ( ! $loaded ) {
				/** Translators: %s is a folder path */
				$new_data = sprintf( __( 'In %s:', 'secupress' ), "<code>$path</code>" );
			}

			// Remove possible nodes not created by us, but with the same node type.
			if ( $node_types ) {
				$node_types = (array) $node_types;

				foreach ( $node_types as $i => $node_type ) {
					if ( $loaded ) {
						$old_nodes = $xpath->query( $path . '/' . $node_type );

						if ( $old_nodes->length > 0 ) {
							foreach ( $old_nodes as $old_node ) {
								$old_node->parentNode->removeChild( $old_node );
							}
						}
					} else {
						$node_types[ $i ] = "<code>$node_type</code>";
					}
				}

				if ( ! $loaded ) {
					$new_data .= '<br/>' . sprintf( __( 'Remove all existing %s tags.', 'secupress' ), wp_sprintf_l( '%l', $node_types ) );
				}
			}

			// Indentation.
			$spaces = explode( '/', trim( $path, '/' ) );
			$spaces = count( $spaces ) - 1;
			$spaces = str_repeat( ' ', $spaces * 2 );

			if ( $loaded ) {
				// Create fragment.
				$fragment = $doc->createDocumentFragment();
				$fragment->appendXML( "\n$spaces  $nodes_string\n$spaces" );

				// Maybe create child nodes and then, prepend new nodes.
				secupress_get_iis7_node( $doc, $xpath, $path, $fragment );
			} else {
				$nodes_string = esc_html( $nodes_string );
				$new_data    .= '<br/>' . sprintf( __( 'Add the following: %s', 'secupress' ), "<pre>\n$spaces  $nodes_string\n$spaces</pre>" );
				$data[]       = $new_data;
			}
		}

		if ( ! $loaded ) {
			$message = sprintf( __( 'Your %1$s file is not writable. Please edit this file, following these instructions: %2$s', 'secupress' ), '<code>web.config</code>', implode( '<br/>', $data ) );
			secupress_add_notice( $message, 'error', 'secupress-activation-file-not-writable' );
			return;
		}

		// Save the file.
		require_once( ABSPATH . 'wp-admin/includes/misc.php' );

		$doc->encoding     = 'UTF-8';
		$doc->formatOutput = true;
		saveDomDocument( $doc, $file_path );
		return;
	}

	// Nginx.
	if ( apply_filters( 'secupress.nginx.notice', true ) ) {
		$message = sprintf( __( 'Since your %1$s file cannot be edited directly, please add the following in your file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '<pre>' . implode( "\n", $rules ) . '</pre>' );
		secupress_add_notice( $message, 'error', 'secupress-activation-file-not-writable' );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** DEACTIVATE ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

register_deactivation_hook( SECUPRESS_FILE, 'secupress_deactivation' );
/**
 * Tell WP what to do when the plugin is deactivated.
 *
 * @since 1.0
 */
function secupress_deactivation() {
	// Make sure we have our toys.
	secupress_load_functions();

	// While the plugin is deactivated, some sites may activate or deactivate other plugins and themes, or change their default user role.
	if ( is_multisite() ) {
		delete_site_option( 'secupress_active_plugins' );
		delete_site_option( 'secupress_active_themes' );
		delete_site_option( 'secupress_default_role' );
	}

	/**
	 * Fires on SecuPress deactivation.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.deactivation' );

	/**
	 * Fires once SecuPress is activated, after the SecuPress's plugins are loaded.
	 *
	 * @since 1.1.4
	 *
	 * @param (array) $args        An empty array to mimic the `$args` parameter from `secupress_deactivate_submodule()`.
	 * @param (bool)  $is_inactive False to mimic the `$is_inactive` parameter from `secupress_deactivate_submodule()`.
	 */
	do_action( 'secupress.plugins.deactivation', array(), false );
}


add_action( 'secupress.plugins.deactivation', 'secupress_maybe_remove_rules_on_deactivation', 10000 );
/**
 * Maybe remove rules from `.htaccess` or `web.config` file on SecuPress deactivation.
 *
 * @since 1.0
 */
function secupress_maybe_remove_rules_on_deactivation() {
	global $is_apache, $is_iis7, $is_nginx;

	// Apache.
	if ( $is_apache ) {
		$home_path  = secupress_get_home_path();
		$file_path  = $home_path . '.htaccess';
		$filesystem = secupress_get_filesystem();

		if ( ! $filesystem->exists( $file_path ) ) {
			// RLY?
			return;
		}

		if ( ! $filesystem->is_writable( $file_path ) ) {
			// If the file is not writable, display a message.
			$message  = sprintf( __( '%s:', 'secupress' ), SECUPRESS_PLUGIN_NAME ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a file name, 2 and 3 are small parts of code. */
				__( 'It seems your %1$s file is not writable, you have to edit it manually. Please remove all rules between %2$s and %3$s.', 'secupress' ),
				'<code>.htaccess</code>',
				'<code># BEGIN SecuPress</code>',
				'<code># END SecuPress</code>'
			);

			secupress_create_deactivation_notice_muplugin( 'apache_remove_rules', $message );
		}

		// Get the whole content of the file.
		$file_content = $filesystem->get_contents( $file_path );

		if ( ! $file_content ) {
			// Nothing? OK.
			return;
		}

		// Remove old content.
		$pattern      = '/# BEGIN SecuPress (.*)# END SecuPress\s*?/isU';
		$file_content = preg_replace( $pattern, '', $file_content );

		// Save the file.
		$filesystem->put_contents( $file_path, $file_content, FS_CHMOD_FILE );
		return;
	}

	// IIS7.
	if ( $is_iis7 ) {
		$home_path  = secupress_get_home_path();
		$file_path  = $home_path . 'web.config';
		$filesystem = secupress_get_filesystem();

		if ( ! $filesystem->exists( $file_path ) ) {
			// RLY?
			return;
		}

		$doc = new DOMDocument();
		$doc->preserveWhiteSpace = false;

		if ( false === $doc->load( $file_path ) ) {
			// If the file is not writable, display a message.
			$message  = sprintf( __( '%s:', 'secupress' ), SECUPRESS_PLUGIN_NAME ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a file name, 2 is a small part of code. */
				__( 'It seems your %1$s file is not writable, you have to edit the file manually. Please remove all nodes with %2$s.', 'secupress' ),
				'<code>web.config</code>',
				'<code>SecuPress</code>'
			);

			secupress_create_deactivation_notice_muplugin( 'iis7_remove_rules', $message );
		}

		// Remove old content.
		$xpath = new DOMXPath( $doc );
		$nodes = $xpath->query( "/configuration/system.webServer/*[starts-with(@name,'SecuPress ') or starts-with(@id,'SecuPress ')]" );

		if ( $nodes->length > 0 ) {
			foreach ( $nodes as $node ) {
				$node->parentNode->removeChild( $node );
			}
		}

		// Save the file.
		$doc->formatOutput = true;
		saveDomDocument( $doc, $file_path );
		return;
	}

	// Nginx.
	if ( $is_nginx ) {
		// Since we can't edit the file, display a message.
		$message  = sprintf( __( '%s:', 'secupress' ), SECUPRESS_PLUGIN_NAME ) . ' ';
		$message .= sprintf(
			/** Translators: 1 and 2 are small parts of code, 3 is a file name. */
			__( 'Your server runs <strong>Nginx</strong>. You have to edit the configuration file manually. Please remove all rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
			'<code># BEGIN SecuPress</code>',
			'<code># END SecuPress</code>',
			'<code>nginx.conf</code>'
		);
		if ( apply_filters( 'secupress.nginx.notice', true ) ) {
			secupress_create_deactivation_notice_muplugin( 'nginx_remove_rules', $message );
		}
	}
}


/**
 * Create a MU plugin that will display an admin notice. When the user click the button, the MU plugin is destroyed.
 * This is used to display a message after SecuPress is deactivated.
 *
 * @since 1.0
 *
 * @param (string) $plugin_id A unique identifier for the MU plugin.
 * @param (string) $message   The message to display.
 */
function secupress_create_deactivation_notice_muplugin( $plugin_id, $message ) {
	static $authenticated;

	if ( ! function_exists( 'wp_validate_auth_cookie' ) ) {
		return;
	}

	if ( ! isset( $authenticated ) ) {
		$authenticated = wp_validate_auth_cookie();
	}

	$filesystem = secupress_get_filesystem();
	$filename   = WPMU_PLUGIN_DIR . "/_secupress_deactivation-notice-{$plugin_id}.php";

	if ( ! $authenticated || $filesystem->exists( $filename ) ) {
		return;
	}

	// Plugin contents.
	$contents = $filesystem->get_contents( SECUPRESS_INC_PATH . 'data/deactivation-mu-plugin.phps' );

	// Add new contents.
	$args = array(
		'{{PLUGIN_NAME}}' => SECUPRESS_PLUGIN_NAME,
		'{{PLUGIN_ID}}'   => $plugin_id,
		'{{MESSAGE}}'     => $message,
		'{{USER_ID}}'     => get_current_user_id(),
		'{{BUTTON_TEXT}}' => __( 'OK, got it!', 'secupress' ),
	);

	$contents = str_replace( array_keys( $args ), $args, $contents );

	if ( ! $filesystem->exists( WPMU_PLUGIN_DIR ) ) {
		$filesystem->mkdir( WPMU_PLUGIN_DIR );
	}

	if ( ! $filesystem->exists( WPMU_PLUGIN_DIR ) ) {
		return;
	}

	$filesystem->put_contents( $filename, $contents );
}

