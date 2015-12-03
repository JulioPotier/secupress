<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * On plugin activation, test if the server has all we need.
 * If not, deactivate.
 *
 * @since 1.0
 */
add_action( 'secupress_activate_plugin_move-login', 'secupress_move_login_validate_server_config' );

function secupress_move_login_validate_server_config() {
	global $is_apache, $is_nginx, $is_iis7;

	// The plugin needs the request uri
	if ( empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) && empty( $_SERVER['REQUEST_URI'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems your server configuration prevent the plugin to work properly. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_request_uri', $message, 'error' );
	}
	// IIS7
	if ( $is_iis7 && ! iis7_supports_permalinks() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems the URL rewrite module is not activated on your server. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_iis7_rewrite', $message, 'error' );
	}
	// Apache
	elseif ( $is_apache && ! got_mod_rewrite() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems the URL rewrite module is not activated on your server. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'no_apache_rewrite', $message, 'error' );
	}
	// None
	elseif ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= __( 'It seems your server does not use <i>Apache</i>, <i>Nginx</i>, nor <i>IIS7</i>. The login page can\'t be moved.', 'secupress' );
		add_settings_error( 'secupress_users-login_settings', 'unknown_os', $message, 'error' );
	}

	// If a message is set, the plugin can't work.
	if ( ! empty( $message ) ) {
		secupress_deactivate_submodule( 'users-login', 'move-login', array( 'no-tests' => 1 ) );
	}
}


/*
 * Remove rewrite rules from `.htaccess` / `web.config` file on plugin deactivation.
 *
 * @since 1.0
 */
add_action( 'secupress_deactivate_plugin_move-login', 'secupress_move_login_deactivate' );

function secupress_move_login_deactivate( $args ) {
	global $is_apache, $is_nginx, $is_iis7;

	if ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		return;
	}
	if ( ! empty( $args['no-tests'] ) ) {
		return;
	}

	// Nginx
	if ( $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 and 2 are small parts of code, 3 is a file name. */
			__( 'It seems your server uses a <i>Nginx</i> system. You have to edit the configuration file manually. Please remove the rewrite rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
			'<code># BEGIN SecuPress move_login</code>',
			'<code># END SecuPress</code>',
			'<code>nginx.conf</code>'
		);////
		add_settings_error( 'secupress_users-login_settings', 'nginx_manual_edit', $message, 'error' );
		return;
	}

	// Apache
	if ( $is_apache ) {
		// Remove the rules from the file.
		if ( ! secupress_move_login_write_apache_rules() ) {
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
			$message .= sprintf(
				/* translators: 1 and 2 are small parts of code, 3 is a file name. */
				__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
				'<code># BEGIN SecuPress move_login</code>',
				'<code># END SecuPress</code>',
				'<code>.htaccess</code>'
			);
			add_settings_error( 'secupress_users-login_settings', 'apache_manual_edit', $message, 'error' );
		}
		return;
	}

	// IIS7
	// Remove the rules from the file.
	if ( ! secupress_move_login_write_iis7_rules() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 is a small part of code, 2 is a file name. */
			__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules with %1$s from the %2$s file.', 'secupress' ),
			'<code>SecuPress move_login</code>',
			'<code>web.config</code>'
		);
		add_settings_error( 'secupress_users-login_settings', 'iis7_manual_edit', $message, 'error' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* ADD REWRITE RULES ============================================================================ */
/*------------------------------------------------------------------------------------------------*/

/*
 * Add rewrite rules into `.htaccess` / `web.config` file when settings are updated.
 *
 * @since 1.0
 */
add_action( 'update_option_secupress_users-login_settings', 'secupress_move_login_activate', 10, 2 );

function secupress_move_login_activate( $old_value, $value ) {
	global $is_apache, $is_nginx, $is_iis7;

	// Not active? Bail out.
	if ( ! secupress_is_submodule_active( 'users-login', 'move-login' ) ) {
		return;
	}

	// Test if rewrite rules have changed.
	$slugs   = secupress_move_login_slug_labels();
	$changed = false;

	foreach ( $slugs as $action => $label ) {
		$option_name = 'move-login_slug-' . $action;

		if ( isset( $old_value[ $option_name ], $value[ $option_name ] ) && $old_value[ $option_name ] !== $value[ $option_name ] ) {
			$changed = true;
			break;
		}
	}

	// No changes? bail out.
	if ( ! $changed ) {
		return;
	}

	// Nginx: we can't edit the file.
	if ( $is_nginx ) {
		$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		/* translators: 1 is a link "the dedicated section", 2 is a file name. */
		$message .= sprintf( __( 'It seems your server uses a <i>Nginx</i> system. You have to edit the configuration file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>nginx.conf</code>' );
		add_settings_error( 'secupress_users-login_settings', 'nginx_manual_edit', $message, 'error' );
		return;
	}

	// Apache
	if ( $is_apache ) {
		if ( ! secupress_move_login_write_apache_rules( secupress_move_login_get_rules() ) ) {
			// File is not writable.
			$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
			/* translators: 1 is a link "the dedicated section", 2 is a file name. */
			$message .= sprintf( __( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>.htaccess</code>' );
			add_settings_error( 'secupress_users-login_settings', 'apache_manual_edit', $message, 'error' );
		}
		return;
	}

	// IIS7
	if ( ! secupress_move_login_write_iis7_rules( secupress_move_login_get_rules() ) ) {
		// File is not writable.
		$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'users-login' ) ) . '#move-login_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Move Login', 'secupress' ) );
		/* translators: 1 is a link "the dedicated section", 2 is a file name. */
		$message .= sprintf( __( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>web.config</code>' );
		add_settings_error( 'secupress_users-login_settings', 'iis7_manual_edit', $message, 'error' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

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


function secupress_move_login_file_is_writable( $file ) {
	$home_path = secupress_get_home_path();

	return wp_is_writable( $home_path . $file ) || ( ! file_exists( $home_path . $file ) && wp_is_writable( $home_path ) );
}


/*------------------------------------------------------------------------------------------------*/
/* APACHE ======================================================================================= */
/*------------------------------------------------------------------------------------------------*/

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
			$out[] = '    RewriteRule ^' . $bases['site_from'] . $slug . '/?$ ' . $bases['site_to'] . $rule . ' [QSA,L]';
		}

		$out[] = '</IfModule>';
	}

	return implode( "\n", $out );
}


/*
 * Add or remove rules in `.htaccess` file.
 *
 * @since 1.0
 *
 * @param (array) $rules  Rules to write.
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_move_login_write_apache_rules( $rules = array() ) {
	$home_path = secupress_get_home_path();

	if ( ! secupress_move_login_file_is_writable( '.htaccess' ) ) {
		return false;
	}

	$rules = secupress_move_login_get_apache_rules( $rules );

	return secupress_write_htaccess( 'move_login', $rules );
}


/*------------------------------------------------------------------------------------------------*/
/* IIS7 ========================================================================================= */
/*------------------------------------------------------------------------------------------------*/

function secupress_move_login_get_iis7_rules( $rules = array() ) {
	$out = array();

	if ( $rules ) {
		$rule_i = 1;
		$marker = 'move_login';
		$space  = str_repeat( ' ', 16 );
		$bases  = secupress_get_rewrite_bases();

		foreach ( $rules as $slug => $rule ) {
			$out[] = $space . '<rule name="SecuPress ' . $marker . ' Rule ' . $rule_i . '" stopProcessing="true">' . "\n"
			       . $space . '    <match url="^' . $bases['site_from'] . $slug . '/?$" ignoreCase="false" />' . "\n"
			       . $space . '    <action type="Redirect" url="' . $bases['site_to'] . $rule . '" redirectType="Permanent" />' . "\n"
			       . $space . "</rule>\n";
			$rule_i++;
		}
	}

	return implode( "\n", $out );
}


/*
 * Add or remove rules in `web.config` file.
 *
 * @since 1.0
 *
 * @param (string|array) Rules to write.
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_move_login_write_iis7_rules( $rules = array() ) {
	$home_path = secupress_get_home_path();

	if ( ! secupress_move_login_file_is_writable( 'web.config' ) ) {
		return false;
	}

	$rules = secupress_move_login_get_iis7_rules( $rules );

	return secupress_insert_iis7_nodes( 'move_login', array( 'nodes_string' => $rules ) );
}


/*------------------------------------------------------------------------------------------------*/
/* NGINX ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

function secupress_move_login_get_nginx_rules( $rules = array() ) {
	$out = array();

	if ( $rules ) {
		$bases = secupress_get_rewrite_bases();
		$out   = array(
			'location ' . $bases['base'] . ' {',
		);

		foreach ( $rules as $slug => $rule ) {
			$out[] = '    rewrite ^' . $bases['site_from'] . $slug . '/?$ /' . $bases['site_to'] . $rule . ' break;';
		}

		$out[] = '}';
	}

	return implode( "\n", $out );
}
