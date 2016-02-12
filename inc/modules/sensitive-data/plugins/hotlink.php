<?php
/*
Module Name: Anti Hotlink
Description: Prevent medias hotlinking.
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ACTIVATION / DEACTIVATION ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * On SecuPress activation and plugin activation, test if the server has what we need.
 * If not, deactivate. If yes, write the rules.
 *
 * @since 1.0
 */
add_action( 'secupress_activate_plugin_hotlink', 'secupress_hotlink_activate' );
add_action( 'secupress.plugins.activation',      'secupress_hotlink_activate' );

function secupress_hotlink_activate() {
	global $is_apache, $is_nginx, $is_iis7;

	// The plugin needs the request uri.
	if ( empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) && empty( $_SERVER['REQUEST_URI'] ) ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		$message .= __( 'It seems your server configuration prevent the plugin to work properly. The anti hotlink can\'t work.', 'secupress' );
		add_settings_error( 'secupress_sensitive-data_settings', 'no_request_uri', $message, 'error' );
	}
	// Hotlink protection won't work over http, it needs SSL to (maybe) get the referer.
	if ( ! secupress_is_site_ssl() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		$message .= __( 'The anti hotlink can work only over SSL (the URL of your website must start with <code>https://</code>).', 'secupress' );
		add_settings_error( 'secupress_sensitive-data_settings', 'no_ssl', $message, 'error' );
	}
	// IIS7
	if ( $is_iis7 ) {
		if ( ! function_exists( 'iis7_supports_permalinks' ) ) {
			require_once( ABSPATH . WPINC . '/functions.php' );
		}
		if ( ! iis7_supports_permalinks() ) {
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
			$message .= __( 'It seems the URL rewrite module is not activated on your server. The anti hotlink can\'t work.', 'secupress' );
			add_settings_error( 'secupress_sensitive-data_settings', 'no_iis7_rewrite', $message, 'error' );
		}
	}
	// Apache
	elseif ( $is_apache ) {
		if ( ! function_exists( 'got_mod_rewrite' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/misc.php' );
		}
		if ( ! got_mod_rewrite() ) {
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
			$message .= __( 'It seems the URL rewrite module is not activated on your server. The anti hotlink can\'t work.', 'secupress' );
			add_settings_error( 'secupress_sensitive-data_settings', 'no_apache_rewrite', $message, 'error' );
		}
	}
	// None
	elseif ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		$message .= __( 'It seems your server does not use <i>Apache</i>, <i>Nginx</i>, nor <i>IIS7</i>. The anti hotlink can\'t work.', 'secupress' );
		add_settings_error( 'secupress_sensitive-data_settings', 'unknown_os', $message, 'error' );
	}

	// If a message is set, the plugin can't work.
	if ( ! empty( $message ) ) {
		// Deactivate the plugin.
		secupress_deactivate_submodule( 'sensitive-data', 'hotlink', array( 'no-tests' => 1 ) );
		return;
	}

	// Rewrite rules must be added to the `.htaccess`/`web.config` file.
	secupress_hotlink_write_rules();
}


/*
 * Remove rewrite rules from the `.htaccess`/`web.config` file on plugin deactivation.
 *
 * @since 1.0
 *
 * @param (array) $args Some parameters.
 */
add_action( 'secupress_deactivate_plugin_hotlink', 'secupress_hotlink_deactivate' );
add_action( 'secupress_deactivation',              'secupress_hotlink_deactivate' );

function secupress_hotlink_deactivate( $args = array() ) {
	global $is_apache, $is_nginx, $is_iis7;

	if ( ! $is_iis7 && ! $is_apache && ! $is_nginx ) {
		return;
	}
	if ( ! empty( $args['no-tests'] ) ) {
		return;
	}

	secupress_hotlink_remove_rules();
}


/*------------------------------------------------------------------------------------------------*/
/* ADD REWRITE RULES ============================================================================ */
/*------------------------------------------------------------------------------------------------*/

/*
 * Add rewrite rules into the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx servers or if the file is not writable.
 *
 * @since 1.0
 */
function secupress_hotlink_write_rules() {
	global $is_apache, $is_nginx, $is_iis7;

	// Nginx: we can't edit the file.
	if ( $is_nginx ) {
		$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'sensitive-data' ) ) . '#hotlink_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		/* translators: 1 is a link "the dedicated section", 2 is a file name. */
		$message .= sprintf( __( 'It seems your server uses a <i>Nginx</i> system. You have to edit the configuration file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>nginx.conf</code>' );
		add_settings_error( 'secupress_sensitive-data_settings', 'nginx_manual_edit', $message, 'error' );
		return;
	}

	// Apache
	if ( $is_apache ) {
		if ( ! secupress_hotlink_write_apache_rules() ) {
			// File is not writable.
			$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'sensitive-data' ) ) . '#hotlink_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
			/* translators: 1 is a link "the dedicated section", 2 is a file name. */
			$message .= sprintf( __( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>.htaccess</code>' );
			add_settings_error( 'secupress_sensitive-data_settings', 'apache_manual_edit', $message, 'error' );
		}
		return;
	}

	// IIS7
	if ( ! secupress_hotlink_write_iis7_rules() ) {
		// File is not writable.
		$link     = '<a href="' . esc_url( secupress_admin_url( 'secupress_scanners', 'sensitive-data' ) ) . '#hotlink_rules">' . __( 'the dedicated section', 'secupress' ) . '</a>';
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		/* translators: 1 is a link "the dedicated section", 2 is a file name. */
		$message .= sprintf( __( 'It seems your %2$s file is not writable. You have to edit the file manually. Please see the rewrite rules provided %1$s and copy/paste it into the %2$s file.', 'secupress' ), $link, '<code>web.config</code>' );
		add_settings_error( 'secupress_sensitive-data_settings', 'iis7_manual_edit', $message, 'error' );
	}
}


/*
 * Remove rewrite rules from the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx servers or if the file is not writable.
 *
 * @since 1.0
 */
function secupress_hotlink_remove_rules() {
	global $is_apache, $is_nginx, $is_iis7;

	// Nginx
	if ( $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 and 2 are small parts of code, 3 is a file name. */
			__( 'It seems your server uses a <i>Nginx</i> system. You have to edit the configuration file manually. Please remove the rewrite rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
			'<code># BEGIN SecuPress hotlink</code>',
			'<code># END SecuPress</code>',
			'<code>nginx.conf</code>'
		);
		add_settings_error( 'secupress_sensitive-data_settings', 'nginx_manual_edit', $message, 'error' );
		return;
	}

	// Apache
	if ( $is_apache ) {
		// Remove the rules from the file.
		if ( ! secupress_hotlink_remove_apache_rules() ) {
			$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
			$message .= sprintf(
				/* translators: 1 and 2 are small parts of code, 3 is a file name. */
				__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
				'<code># BEGIN SecuPress hotlink</code>',
				'<code># END SecuPress</code>',
				'<code>.htaccess</code>'
			);
			add_settings_error( 'secupress_sensitive-data_settings', 'apache_manual_edit', $message, 'error' );
		}
		return;
	}

	// IIS7
	// Remove the rules from the file.
	if ( ! secupress_hotlink_remove_iis7_rules() ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), __( 'Anti Hotlink', 'secupress' ) );
		$message .= sprintf(
			/* translators: 1 is a small part of code, 2 is a file name. */
			__( 'It seems your %2$s file is not writable. You have to edit the file manually. Please remove the rewrite rules with %1$s from the %2$s file.', 'secupress' ),
			'<code>SecuPress hotlink</code>',
			'<code>web.config</code>'
		);
		add_settings_error( 'secupress_sensitive-data_settings', 'iis7_manual_edit', $message, 'error' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Tell if a file located in the home folder is writable.
 * If the file does not exist, tell if the home folder is writable.
 *
 * @since 1.0
 *
 * @param (string) $file File name.
 *
 * @return (bool)
 */
function secupress_hotlink_file_is_writable( $file ) {
	$home_path = secupress_get_home_path();

	return wp_is_writable( $home_path . $file ) || ( ! file_exists( $home_path . $file ) && wp_is_writable( $home_path ) );
}


/*
 * Get a list of autorized referers as regex patterns.
 *
 * @since 1.0
 *
 * @return (array) A list of regex patterns.
 */
function secupress_hotlink_get_referer_regex_patterns_list() {
	$refs = array();
	/**
	 * Add autorized referers. Current domain will ba added later.
	 *
	 * @since 1.0
	 *
	 * @param (array) $refs An array of autorized referers.
	 */
	$refs = apply_filters( 'secupress.plugin.hotlink.additional_autorized_referers', $refs );

	if ( $refs ) {
		foreach ( $refs as $i => $ref ) {
			$ref  = rtrim( $ref, '/' );
			$ref  = addcslashes( $ref, '[](){}.*+?|^$' );
			$ref  = preg_replace( '/^https?:/', '^https?:', $ref );
			$ref .= '(?:/?|/.+)$';
		}
	}

	// Add the current domain as an autorized referer.
	$home_url = home_url();
	$home_url = rtrim( $home_url, '/' );

	if ( is_multisite() && is_subdomain_install() ) {
		$home_url = preg_replace( '/^https?:\/\//', '', $home_url );
		$home_url = addcslashes( $home_url, '[](){}.*+?|^$' );
		$home_url = '^https?://([^.]+\.)?' . $home_url;
	} else {
		$home_url = addcslashes( $home_url, '[](){}.*+?|^$' );
		$home_url = preg_replace( '/^https?:/', '^https?:', $home_url );
	}

	$home_url .= '(?:/?|/.+)$';
	array_unshift( $refs, $home_url );

	return $refs;
}


/*
 * Get a list of protected file extensions as a regex pattern.
 *
 * @since 1.0
 *
 * @return (string) A regex pattern.
 */
function secupress_hotlink_get_protected_extensions_regex_pattern() {
	$ext = array( 'jpg', 'jpeg', 'png', 'gif' );
	/**
	 * Filter the list of protected file extensions.
	 *
	 * @since 1.0
	 *
	 * @param (array) $ext An array of file extensions.
	 */
	$ext = apply_filters( 'secupress.plugin.hotlink.protected_extensions', $ext );

	return '\.(' . implode( '|', $ext ) . ')$';
}


/*
 * Get the URL of the image replacement.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_hotlink_get_replacement_url() {
	$url = SECUPRESS_FRONT_IMAGES_URL . 'hotlink.png';
	/**
	 * Filter the URL of the image used as replacement when a media is hotlinked.
	 *
	 * @since 1.0
	 *
	 * @param (string) $url The replacement image URL.
	 */
	return apply_filters( 'secupress.plugin.hotlink.replacement_url', $url );
}


/*
 * Get the URI of the image replacement as a regex pattern. The aim is to use it in `RewriteCond`.
 *
 * @since 1.0
 *
 * @return (string|bool) A regex pattern that matches the image replacement URI. False if the image is not delivered from the same domain.
 */
function secupress_hotlink_get_replacement_regex_pattern() {
	$url = secupress_hotlink_get_replacement_url();

	if ( false === strpos( $url, $_SERVER['HTTP_HOST'] ) ) {
		return false;
	}

	$url = explode( $_SERVER['HTTP_HOST'], $url );
	$url = end( $url );
	$url = addcslashes( $url, '[](){}.*+?|^$' );

	return $url;
}


/*------------------------------------------------------------------------------------------------*/
/* APACHE ======================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/*
 * Get the rewrite rules that should be added into the `.htaccess` file (without the SecuPress marker).
 * Will output something like:
 * <IfModule mod_rewrite.c>
 *     RewriteEngine On
 *     RewriteCond %{REQUEST_FILENAME} -f
 *     RewriteCond %{REQUEST_FILENAME} \.(jpg|jpeg|png|gif)$ [NC]
 *     RewriteCond %{HTTP_REFERER} !^$
 *     RewriteCond %{HTTP_REFERER} !^https?://www\.domain\.com(?:/?|/.+)$ [NC]
 *     RewriteCond %{REQUEST_URI} !^/wp-content/plugins/secupress-free/assets/front/images/hotlink\.png$ [NC]
 *     RewriteRule \.(jpg|jpeg|png|gif)$ https://www.domain.com/wp-content/plugins/secupress-free/assets/front/images/hotlink.png [NC,R,L]
 * </IfModule>
 *
 * @since 1.0
 * @see https://perishablepress.com/creating-the-ultimate-htaccess-anti-hotlinking-strategy/
 *
 * @return (string) The rewrite rules, ready to be insterted into the `.htaccess` file.
 */
function secupress_hotlink_get_apache_rules() {
	$refs     = secupress_hotlink_get_referer_regex_patterns_list();
	$ext      = secupress_hotlink_get_protected_extensions_regex_pattern();
	$repl     = secupress_hotlink_get_replacement_url();
	$uri_cond = secupress_hotlink_get_replacement_regex_pattern();

	$out  = "<IfModule mod_rewrite.c>\n";
		$out .= "    RewriteEngine On\n";
		// An existing file.
		$out .= "    RewriteCond %{REQUEST_FILENAME} -f\n";
		// A file with one of the protected extensions.
		$out .= "    RewriteCond %{REQUEST_FILENAME} $ext [NC]\n";
		// Allow empty referer.
		$out .= "    RewriteCond %{HTTP_REFERER} !^$\n";
		// Allowed referers.
		foreach ( $refs as $ref ) {
			$out .= "    RewriteCond %{HTTP_REFERER} !$ref [NC]\n";
		}
		// The URI must not match the replacement image (infinite redirections).
		if ( $uri_cond ) {
			$out .= "    RewriteCond %{REQUEST_URI} !^$uri_cond$ [NC]\n";
		}
		// Redirect to the replacement image.
		$out .= "    RewriteRule $ext $repl [NC,R,L]\n";
	$out .= '</IfModule>';

	return $out;
}


/*
 * Add rules into the `.htaccess` file.
 *
 * @since 1.0
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_hotlink_write_apache_rules() {

	if ( ! secupress_hotlink_file_is_writable( '.htaccess' ) ) {
		return false;
	}

	$rules = secupress_hotlink_get_apache_rules();

	return secupress_write_htaccess( 'hotlink', $rules );
}


/*
 * Remove rules from the `.htaccess` file.
 *
 * @since 1.0
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_hotlink_remove_apache_rules() {

	if ( ! secupress_hotlink_file_is_writable( '.htaccess' ) ) {
		return false;
	}

	return secupress_write_htaccess( 'hotlink' );
}


/*------------------------------------------------------------------------------------------------*/
/* IIS7 ========================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/*
 * Get the rewrite rules that should be added into the `web.config` file.
 * Will output something like:
 * <rule name="SecuPress hotlink">
 *     <match url="\.(jpg|jpeg|png|gif)$"/>
 *     <conditions>
 *         <add input="{REQUEST_FILENAME}" matchType="isFile"/>
 *         <add input="{REQUEST_FILENAME}" pattern="\.(jpg|jpeg|png|gif)$" ignoreCase="true"/>
 *         <add input="{HTTP_REFERER}" pattern="^$" negate="true"/>
 *         <add input="{HTTP_REFERER}" pattern="^https?://www\.domain\.com(?:/?|/.+)$" negate="true" ignoreCase="true"/>
 *         <add input="{REQUEST_URI}" pattern="^/wp-content/plugins/secupress-free/assets/front/images/hotlink\.png$" negate="true" ignoreCase="true"/>
 *     </conditions>
 *     <action type="Rewrite" url="https://www.domain.com/wp-content/plugins/secupress-free/assets/front/images/hotlink.png" />
 * </rule>
 *
 * @since 1.0
 * @see https://www.iis.net/learn/extensions/url-rewrite-module/url-rewrite-module-configuration-reference
 * @see http://www.it-notebook.org/iis/article/prevent_hotlinking_url_rewrite.htm
 *
 * @return (string) The rewrite rules, ready to be insterted into the `web.config` file.
 */
function secupress_hotlink_get_iis7_rules() {
	$refs     = secupress_hotlink_get_referer_regex_patterns_list();
	$ext      = secupress_hotlink_get_protected_extensions_regex_pattern();
	$repl     = secupress_hotlink_get_replacement_url();
	$uri_cond = secupress_hotlink_get_replacement_regex_pattern();
	$marker   = 'hotlink';
	$spaces   = str_repeat( ' ', 10 );

	$out  = "<rule name=\"SecuPress $marker\">\n";
		$out .= "$spaces  <match url=\"$ext\"/>\n";
		$out .= "$spaces  <conditions>\n";
			$out .= "$spaces    <add input=\"{REQUEST_FILENAME}\" matchType=\"isFile\"/>\n";
			$out .= "$spaces    <add input=\"{REQUEST_FILENAME}\" pattern=\"$ext\" ignoreCase=\"true\"/>\n";
			$out .= "$spaces    <add input=\"{HTTP_REFERER}\" pattern=\"^$\" negate=\"true\"/>\n";
			foreach ( $refs as $ref ) {
				$out .= "$spaces    <add input=\"{HTTP_REFERER}\" pattern=\"$ref\" negate=\"true\" ignoreCase=\"true\"/>\n";
			}
			if ( $uri_cond ) {
				$out .= "$spaces    <add input=\"{REQUEST_URI}\" pattern=\"^$uri_cond$\" negate=\"true\" ignoreCase=\"true\"/>\n";
			}
		$out .= "$spaces  </conditions>\n";
		$out .= "$spaces  <action type=\"Rewrite\" url=\"$repl\" />\n";
	$out .= "$spaces</rule>";

	return $out;
}


/*
 * Add rules into the `web.config` file.
 *
 * @since 1.0
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_hotlink_write_iis7_rules() {

	if ( ! secupress_hotlink_file_is_writable( 'web.config' ) ) {
		return false;
	}

	$rules = secupress_hotlink_get_iis7_rules();

	return secupress_insert_iis7_nodes( 'hotlink', array( 'nodes_string' => $rules ) );
}


/*
 * Remove rules from the `web.config` file.
 *
 * @since 1.0
 *
 * @return (bool) true on succes, false on failure.
 */
function secupress_hotlink_remove_iis7_rules() {

	if ( ! secupress_hotlink_file_is_writable( 'web.config' ) ) {
		return false;
	}

	return secupress_insert_iis7_nodes( 'hotlink' );
}


/*------------------------------------------------------------------------------------------------*/
/* NGINX ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Get the rewrite rules that should be added into the `nginx.conf` file (without the SecuPress marker).
 * Will output something like:
 * if (-f $request_filename) {
 *     set $cond_hotlink 1$cond_hotlink;
 * }
 * if ($request_filename ~* "\.(jpg|jpeg|png|gif)$") {
 *     set $cond_hotlink 2$cond_hotlink;
 * }
 * if ($http_referer !~ "^$") {
 *     set $cond_hotlink 3$cond_hotlink;
 * }
 * if ($http_referer !~* "^https?:\/\/www\.domain\.com(?:\/?|\/.+)$") {
 *     set $cond_hotlink 4$cond_hotlink;
 * }
 * if ($uri !~* "^\/wp-content\/plugins\/secupress-free\/assets\/front\/images\/hotlink\.png$") {
 *     set $cond_hotlink 5$cond_hotlink;
 * }
 * if ($cond_hotlink = "54321") {
 *     rewrite \.(jpg|jpeg|png|gif)$ http://www.domain.com/wp-content/plugins/secupress-free/assets/front/images/hotlink.png redirect;
 * }
 *
 * @since 1.0
 *
 * @return (string) The rewrite rules, ready to be insterted into the `nginx.conf` file.
 */
function secupress_hotlink_get_nginx_rules() {
	$refs     = secupress_hotlink_get_referer_regex_patterns_list();
	$ext      = secupress_hotlink_get_protected_extensions_regex_pattern();
	$repl     = secupress_hotlink_get_replacement_url();
	$uri_cond = secupress_hotlink_get_replacement_regex_pattern();
	$base     = secupress_get_rewrite_bases();
	$base     = $base['base'];
	$marker   = 'hotlink';
	$i        = 3;
	$rule_val = '321';

	$out  = "location $base {\n";
		$out .= '    if (-f $request_filename) {' . "\n";
		$out .= '        set $cond_hotlink 1$cond_hotlink;' . "\n";
		$out .= "    }\n";
		$out .= '    if ($request_filename ~* "' . $ext . '") {' . "\n";
		$out .= '        set $cond_hotlink 2$cond_hotlink;' . "\n";
		$out .= "    }\n";
		$out .= '    if ($http_referer !~ "^$") {' . "\n";
		$out .= '        set $cond_hotlink 3$cond_hotlink;' . "\n";
		$out .= "    }\n";
		foreach ( $refs as $ref ) {
			++$i;
			$rule_val = $i . $rule_val;
			$out .= '    if ($http_referer !~ "' . $ref . '") {' . "\n";
			$out .= '        set $cond_hotlink ' . $i . '$cond_hotlink;' . "\n";
			$out .= "    }\n";
		}
		if ( $uri_cond ) {
			++$i;
			$rule_val = $i . $rule_val;
			$out .= '    if ($uri !~* "' . $uri_cond . '") {' . "\n";
			$out .= '        set $cond_hotlink ' . $i . '$cond_hotlink;' . "\n";
			$out .= "    }\n";
		}
		$out .= '    if ($cond_hotlink = "' . $rule_val . '") {' . "\n";
		$out .= "        rewrite $ext $repl redirect;\n";
		$out .= "    }\n";
	$out .= '}';

	return $out;
}
