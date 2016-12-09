<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'secupress.modules.activate_submodule_move-login', 'secupress_move_login_activate' );
/**
 * On module activation, test if the server has what we need.
 * If not, deactivate. If yes, write the rules.
 *
 * @since 1.0
 *
 * @param (bool) $was_active True if Move Login was already active.
 */
function secupress_move_login_activate( $was_active ) {
	global $is_apache, $is_nginx, $is_iis7;

	// The plugin needs the request uri.
	if ( empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) && empty( $_SERVER['REQUEST_URI'] ) ) {
		$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
		$message .= __( 'It seems your server configuration prevents the plugin from working properly. The login page cannot be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_request_uri', $message, 'error' );
	}
	// Server not supported.
	if ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
		$message .= __( 'It seems your server does not use <strong>Apache</strong>, <strong>Ngnix</strong>, or <strong>IIS7</strong>. The login page cannot be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'unknown_os', $message, 'error' );
	}

	// If a message is set, the plugin can't work.
	if ( ! empty( $message ) ) {
		// Deactivate the plugin silently.
		secupress_deactivate_submodule_silently( 'users-login', 'move-login' );
		return;
	}

	if ( ! $was_active ) {
		/**
		 * Triggers when Move Login is activated, before writting rules.
		 *
		 * @since 1.1.3
		 * @author Grégory Viguier
		 */
		do_action( 'secupress.plugin.move_login.activate' );
	}

	// Rewrite rules must be added to the `.htaccess`/`web.config` file.
	secupress_move_login_write_rules();
}


add_action( 'secupress.modules.deactivate_submodule_move-login', 'secupress_move_login_deactivate', 10, 2 );
/**
 * On module deactivation, remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 *
 * @param (array) $args         Some arguments.
 * @param (bool)  $was_inactive True if Move Login was already inactive.
 */
function secupress_move_login_deactivate( $args, $was_inactive ) {
	if ( ! $was_inactive ) {
		/**
		 * Triggers when Move Login is deactivated, before removing rules.
		 *
		 * @since 1.1.3
		 * @author Grégory Viguier
		 */
		do_action( 'secupress.plugin.move_login.deactivate' );
	}

	secupress_remove_module_rules_or_notice( 'move_login', __( 'Move Login', 'secupress' ) );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_move_login_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_move_login_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;

	// The plugin needs the request uri.
	if ( empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) && empty( $_SERVER['REQUEST_URI'] ) ) {
		// Deactivate the plugin.
		secupress_deactivate_submodule_silently( 'users-login', 'move-login' );
		return $rules;
	}
	// Server not supported.
	if ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		// Deactivate the plugin.
		secupress_deactivate_submodule_silently( 'users-login', 'move-login' );
		return $rules;
	}

	// Add the rules.
	$marker = 'move_login';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_move_login_get_apache_rules( secupress_move_login_get_rules() );
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_move_login_get_iis7_rules( secupress_move_login_get_rules() ) );
	} else {
		$rules[ $marker ] = secupress_move_login_get_nginx_rules( secupress_move_login_get_rules() );
	}

	return $rules;
}


/*------------------------------------------------------------------------------------------------*/
/* UPDATE SETTINGS ============================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'update_option_secupress_users-login_settings', 'secupress_move_login_write_rules_on_update', 11, 2 );
/**
 * Add rewrite rules into the `.htaccess`/`web.config` file when settings are updated.
 *
 * @since 1.0
 *
 * @param (array) $old_value Old value of the whole module option.
 * @param (array) $value     New value of the whole module option.
 */
function secupress_move_login_write_rules_on_update( $old_value, $value ) {
	global $is_apache, $is_nginx, $is_iis7;

	if ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		return;
	}

	// Not active? Bail out.
	if ( ! secupress_is_submodule_active( 'users-login', 'move-login' ) ) {
		return;
	}

	// Write the rewrite rules only if they have changed.
	$slugs   = secupress_move_login_slug_labels();
	$changed = false;

	foreach ( $slugs as $action => $label ) {
		$option_name = 'move-login_slug-' . $action;

		if ( empty( $old_value[ $option_name ] ) || isset( $old_value[ $option_name ], $value[ $option_name ] ) && $old_value[ $option_name ] !== $value[ $option_name ] ) {
			$changed = true;
			break;
		}
	}

	if ( $changed ) {
		secupress_move_login_write_rules();
	}
}


add_action( 'update_site_option_secupress_users-login_settings', 'secupress_move_login_write_rules_on_network_update', 10, 3 );
/**
 * Add rewrite rules into the `.htaccess`/`web.config` file when settings are (network) updated.
 *
 * @since 1.0
 *
 * @param (string) $option    Name of the network option.
 * @param (array)  $value     New value of the whole module option.
 * @param (array)  $old_value Old value of the whole module option.
 */
function secupress_move_login_write_rules_on_network_update( $option, $value, $old_value ) {
	secupress_move_login_write_rules_on_update( $old_value, $value );
}


/*------------------------------------------------------------------------------------------------*/
/* ADD/REMOVE REWRITE RULES ===================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Add rewrite rules into the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx servers or if the file is not writable.
 *
 * @since 1.0
 */
function secupress_move_login_write_rules() {
	global $is_apache, $is_nginx, $is_iis7;
	static $error_message_done = false;
	$success = false;

	// Apache.
	if ( $is_apache ) {
		$success = secupress_move_login_write_apache_rules( secupress_move_login_get_rules() );

		if ( ! $success && ! $error_message_done ) {
			$error_message_done = true;

			// File is not writable.
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a link "the dedicated section", 2 is a file name. */
				__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ),
				'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>',
				'<code>.htaccess</code>'
			);
			add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
		}
	}

	// IIS7.
	if ( $is_iis7 ) {
		$success = secupress_move_login_write_iis7_rules( secupress_move_login_get_rules() );

		if ( ! $success && ! $error_message_done ) {
			$error_message_done = true;

			// File is not writable.
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a link "the dedicated section", 2 is a file name. */
				__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ),
				'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>',
				'<code>web.config</code>'
			);
			add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		}
	}

	// Nginx.
	if ( $is_nginx && ! $error_message_done ) {
		$error_message_done = true;

		// We can't edit the file.
		$message  = sprintf( __( '%s:', 'secupress' ), __( 'Move Login', 'secupress' ) ) . ' ';
		$message .= sprintf(
			/** Translators: 1 is a file name, 2 is a link "the dedicated section". */
			__( 'Your server runs <strong>Ngnix</strong>. You have to edit the configuration file manually. Please see the rewrite rules provided %2$s and copy/paste it into the %1$s file.', 'secupress' ),
			'<code>nginx.conf</code>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>'
		);
		add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
	}

	/**
	 * Triggers after rules have been written (or not).
	 *
	 * @since 1.1.3
	 * @author Grégory Viguier
	 *
	 * @param (bool) $success Tell if the rules have been successfully written into the file.
	 */
	do_action( 'secupress.plugin.move_login.write_rules', $success );
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Get generic rules for the rewrite rules, based on the settings.
 *
 * @since 1.0
 *
 * @return (array) An array with the rewritted URIs as keys and the real URIs as values.
 */
function secupress_move_login_get_rules() {
	$slugs = secupress_move_login_get_default_slugs();
	$rules = array();

	foreach ( $slugs as $action ) {
		$slug = secupress_get_module_option( 'move-login_slug-' . $action, $action, 'users-login' );
		$slug = sanitize_title( $slug, $action, 'display' );
		$rules[ $slug ] = 'wp-login.php' . ( 'login' === $action ? '' : '?action=' . $action );
	}

	return $rules;
}


/*------------------------------------------------------------------------------------------------*/
/* APACHE ======================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * Get the rewrite rules that should be added into the `.htaccess` file (without the SecuPress marker).
 *
 * @since 1.0
 *
 * @param (array) $rules Generic rules to write (see `secupress_move_login_get_rules()`).
 *
 * @return (string) The rewrite rules, ready to be insterted into the `.htaccess` file.
 */
function secupress_move_login_get_apache_rules( $rules = array() ) {
	$out = array();

	if ( $rules ) {
		$bases = secupress_get_rewrite_bases();
		$out   = array(
			'<IfModule mod_rewrite.c>',
			'    RewriteEngine On',
			'    RewriteBase ' . $bases['base'],
		);

		foreach ( $rules as $slug => $rule ) {
			$out[] = '    RewriteRule ^' . $bases['site_from'] . $slug . '/?$ ' . $bases['site_dir'] . $rule . ' [QSA,L]';
		}

		$out[] = '</IfModule>';
	}

	return implode( "\n", $out );
}


/**
 * Add or remove rules into the `.htaccess` file.
 *
 * @since 1.0
 *
 * @param (array) $rules Generic rules to write (see `secupress_move_login_get_rules()`).
 *
 * @return (bool) true on success, false on failure.
 */
function secupress_move_login_write_apache_rules( $rules = array() ) {

	if ( ! secupress_root_file_is_writable( '.htaccess' ) ) {
		return false;
	}

	$rules = secupress_move_login_get_apache_rules( $rules );

	return secupress_write_htaccess( 'move_login', $rules );
}


/*------------------------------------------------------------------------------------------------*/
/* IIS7 ========================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * Get the rewrite rules that should be added into the `web.config` file.
 *
 * @since 1.0
 *
 * @param (array) $rules Generic rules to write (see `secupress_move_login_get_rules()`).
 *
 * @return (string) The rewrite rules, ready to be insterted into the `web.config` file.
 */
function secupress_move_login_get_iis7_rules( $rules = array() ) {
	$out = array();

	if ( $rules ) {
		$rule_i = 1;
		$marker = 'move_login';
		$space  = str_repeat( ' ', 8 );
		$bases  = secupress_get_rewrite_bases();

		foreach ( $rules as $slug => $rule ) {
			$out[] = $space . '<rule name="SecuPress ' . $marker . ' Rule ' . $rule_i . '" stopProcessing="true">' . "\n"
			       . $space . '  <match url="^' . $bases['site_from'] . $slug . '/?$" ignoreCase="false" />' . "\n"
			       . $space . '  <action type="Redirect" url="' . $bases['site_dir'] . $rule . '" redirectType="Permanent" />' . "\n"
			       . $space . "</rule>\n";
			$rule_i++;
		}
	}

	return implode( "\n", $out );
}


/**
 * Add or remove rules into the `web.config` file.
 *
 * @since 1.0
 *
 * @param (array) $rules Generic rules to write (see `secupress_move_login_get_rules()`).
 *
 * @return (bool) true on success, false on failure.
 */
function secupress_move_login_write_iis7_rules( $rules = array() ) {

	if ( ! secupress_root_file_is_writable( 'web.config' ) ) {
		return false;
	}

	$rules = secupress_move_login_get_iis7_rules( $rules );

	return secupress_insert_iis7_nodes( 'move_login', array( 'nodes_string' => $rules ) );
}


/*------------------------------------------------------------------------------------------------*/
/* NGINX ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Get the rewrite rules that should be added into the `nginx.conf` file (without the SecuPress marker).
 *
 * @since 1.0
 *
 * @param (array) $rules Generic rules to write (see `secupress_move_login_get_rules()`).
 *
 * @return (string) The rewrite rules, ready to be insterted into the `nginx.conf` file.
 */
function secupress_move_login_get_nginx_rules( $rules = array() ) {
	$out = '';

	if ( $rules ) {
		$marker = 'move_login';
		$bases  = secupress_get_rewrite_bases();
		$out    = "# BEGIN SecuPress $marker\n";

		foreach ( $rules as $slug => $rule ) {
			$out .= 'rewrite ^' . $bases['site_from'] . $slug . '/?$ ' . $bases['site_dir'] . $rule . " last;\n";
		}

		$out   .= "# END SecuPress\n";
	}

	return $out;
}
