<?php
/**
 * Module Name: Bad URL Access
 * Description: Deny access to some sensitive files.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 1.1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activation', 'secupress_bad_url_access_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 * @since 1.0.2 Return a boolean.
 * @author Grégory Viguier
 *
 * @return (bool) True if rules have been successfully written. False otherwise.
 */
function secupress_bad_url_access_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_bad_url_access_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_bad_url_access_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_bad_url_access_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	return secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'bad_url_access',
		'title'  => __( 'Bad URL Access', 'secupress' ),
	) );
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_url_access_activate_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 */
function secupress_bad_url_access_activate_file() {
	secupress_bad_url_access_activation();
	secupress_scanit( 'Bad_URL_Access', 3 );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_url_access_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_bad_url_access_deactivate() {
	secupress_remove_module_rules_or_notice( 'bad_url_access', __( 'Bad URL Access', 'secupress' ) );
	secupress_scanit( 'Bad_URL_Access', 3 );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_bad_url_access_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_bad_url_access_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'bad_url_access';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_bad_url_access_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_bad_url_access_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_bad_url_access_nginx_rules();
	}

	return $rules;
}


add_action( 'secupress.upgrade', 'secupress_bad_url_access_upgrade', 10, 2 );
/**
 * Fires when SecuPress is upgraded.
 *
 * @since 1.0.2
 * @author Grégory Viguier
 *
 * @param (string) $new_version    The version being upgraded to.
 * @param (string) $actual_version The previous version.
 */
function secupress_bad_url_access_upgrade( $new_version, $actual_version ) {
	global $is_apache, $is_nginx, $is_iis7, $wp_settings_errors;
	$marker = 'bad_url_access';

	if ( ! $is_apache && ! $is_nginx && ! $is_iis7 ) {
		return;
	}

	if ( version_compare( $actual_version, '1.1.4', '<' ) ) {
		/**
		 * 1.0 had a bug preventing TinyMCE to work on some Apache/IIS servers.
		 * 1.0.1 fixed the bug but the wrong rules remained in the `.htaccess`/`web.config` file.
		 * 1.0.2 remove the old rules and add the new ones back.
		 * 1.1.4 added `wp-config.php` to the list of files to protect.
		 */
		if ( secupress_bad_url_access_activation() || $is_nginx ) {
			return;
		}

		// The file is not writable, replace the error message (brace yourself, it gets uggly).
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( ! $last_error || 'general' !== $last_error['setting'] ) {
			return;
		}

		if ( $is_apache && 'apache_manual_edit' === $last_error['code'] ) {
			array_pop( $wp_settings_errors );

			$rules    = esc_html( secupress_bad_url_access_apache_rules() );
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Bad URL Access', 'secupress' ) ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a file name; 2, 3 and 4 are some code. */
				__( 'Your %1$s file is not writable. Please replace previous lines between %2$s and %3$s by the following ones: %4$s', 'secupress' ),
				'<code>.htaccess</code>',
				"<code># BEGIN SecuPress $marker</code>",
				'<code># END SecuPress</code>',
				"<pre># BEGIN SecuPress $marker\n$rules# END SecuPress</pre>"
			);
			secupress_add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
		}

		if ( $is_iis7 && 'iis7_manual_edit' === $last_error['code'] ) {
			array_pop( $wp_settings_errors );

			$path     = '/configuration/system.webServer/rewrite/rules';
			$spaces   = explode( '/', trim( $path, '/' ) );
			$spaces   = count( $spaces ) - 1;
			$spaces   = str_repeat( ' ', $spaces * 2 );
			$rules    = esc_html( secupress_bad_url_access_apache_rules() );
			$message  = sprintf( __( '%s:', 'secupress' ), __( 'Bad URL Access', 'secupress' ) ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a file name, 2 is a tag name, 3 is a folder path (kind of), 4 is some code */
				__( 'Your %1$s file is not writable. Please replace previous rules with %2$s from the tags hierarchy %3$s by the following ones: %4$s', 'secupress' ),
				'<code>web.config</code>',
				'<code>name="SecuPress ' . $marker . '"</code>',
				'<code class="secupress-iis7-path">' . $path . '</code>',
				"<pre>{$spaces}{$rules}</pre>"
			);
			secupress_add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		}
	}
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Bad URL Access: get rules for apache.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_apache_rules() {
	$pattern   = secupress_bad_url_access_get_regex_pattern();
	$bases     = secupress_get_rewrite_bases();
	$base      = $bases['base'];
	$site_from = $bases['site_from'];

	// Trigger a 404 error, because forbidding access to a file is nice, but making it also invisible is more fun :).
	$rules  = "<IfModule mod_rewrite.c>\n";
	$rules .= "    RewriteEngine On\n";
	$rules .= "    RewriteBase $base\n";
	$rules .= "    RewriteCond %{REQUEST_URI} !{$site_from}wp-includes/js/tinymce/wp-tinymce\.php$\n";
	$rules .= "    RewriteRule $pattern [R=404,L,NC]\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * Bad URL Access: get rules for iis7.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_iis7_rules() {
	$marker    = 'bad_url_access';
	$spaces    = str_repeat( ' ', 8 );
	$pattern   = secupress_bad_url_access_get_regex_pattern();
	$bases     = secupress_get_rewrite_bases();
	$site_from = $bases['site_from'];

	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "$spaces  <match url=\"$pattern\"/ ignoreCase=\"true\">\n";
	$rules .= "$spaces  <conditions>\n";
	$rules .= "$spaces    <add input=\"{REQUEST_URI}\" pattern=\"{$site_from}wp-includes/js/tinymce/wp-tinymce\.php$\" negate=\"true\"/>\n";
	$rules .= "$spaces  </conditions>\n";
	$rules .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
	$rules .= "$spaces</rule>";

	return $rules;
}


/**
 * Bad URL Access: get rules for nginx.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_nginx_rules() {
	$marker  = 'bad_url_access';
	$bases   = secupress_get_rewrite_bases();
	// We add the TinyMCE file directly in the pattern.
	$pattern = '^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . 'wp-config\.php|' . $bases['site_from'] . WPINC . '/((?:(?!js/tinymce/wp-tinymce).)+)\.php|' . $bases['site_from'] . 'wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$';

	$rules = "
server {
	# BEGIN SecuPress $marker
	location ~* $pattern {
		return 404;
	}
	# END SecuPress
}";

	return trim( $rules );
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get a regex pattern matching the files.
 *
 * @since 1.0.3
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_get_regex_pattern() {
	$bases = secupress_get_rewrite_bases();
	/**
	 * ^/php\.ini$
	 *
	 * ^/wp-config\.php$
	 *
	 * ^/wp-admin/admin-functions\.php$
	 * ^/wp-admin/install\.php$
	 * ^/wp-admin/menu-header\.php$
	 * ^/wp-admin/setup-config\.php$
	 * ^/wp-admin/upgrade-functions\.php$
	 *
	 * ^/wp-admin/menu\.php$
	 * ^/wp-admin/user/menu\.php$
	 * ^/wp-admin/network/menu\.php$
	 *
	 * ^/wp-admin/includes/.+\.php$
	 *
	 * ^/wp-includes/.+\.php$
	 */
	return '^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . 'wp-config\.php|' . $bases['site_from'] . WPINC . '/.+\.php|' . $bases['site_from'] . 'wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$';
}
