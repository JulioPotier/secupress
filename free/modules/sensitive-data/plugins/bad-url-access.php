<?php
/**
 * Module Name: Bad URL Access
 * Description: Deny access to some sensitive files.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 2.3.13
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

	switch( true ) {
		case $is_apache:
			$rules = secupress_bad_url_access_apache_rules();
		break;
		case $is_nginx:
			$rules = secupress_bad_url_access_nginx_rules();
		break;
		case $is_iis7:
			$rules = secupress_bad_url_access_iis7_rules();
		break;
		default:
			$rules = '';
		break;
	}

	return secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'bad_url_access',
		'title'  => __( 'Bad URL Access', 'secupress' ),
	) );
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_url_access_activate' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 * @author Julio Potier
 */
function secupress_bad_url_access_activate() {
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
 * @return (array) Rules to write.
 */
function secupress_bad_url_access_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'bad_url_access';

	switch( true ) {
		case $is_apache:
			$rules[ $marker ] = secupress_bad_url_access_apache_rules();
		break;
		case $is_nginx:
			$rules[ $marker ] = secupress_bad_url_access_nginx_rules();
		break;
		case $is_iis7:
			$rules[ $marker ] = [ 'nodes_string' => secupress_bad_url_access_iis7_rules() ];
		break;
		default:
			$rules[ $marker ] = '';
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get rules for apache.
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
 * Get rules for nginx.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_nginx_rules() {
	$marker     = 'bad_url_access';
	$bases      = secupress_get_rewrite_bases();
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

/**
 * Get rules for iis7.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_bad_url_access_iis7_rules() {
	$marker         = 'bad_url_access';
	$patterns       = secupress_bad_url_access_get_regex_pattern();
	$bases          = secupress_get_rewrite_bases();
	$site_from      = '/' . $bases['site_from'];

	$spaces = str_repeat( ' ', 8 );
	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "$spaces  <match url=\"$pattern\"/ ignoreCase=\"true\">\n";
	$rules .= "$spaces  <conditions>\n";
	$rules .= "$spaces    <add input=\"{REQUEST_URI}\" pattern=\"{$site_from}wp-includes/js/tinymce/wp-tinymce\.php$\" negate=\"true\"/>\n";
	$rules .= "$spaces  </conditions>\n";
	$rules .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
	$rules .= "$spaces</rule>";

	return trim( $rules );
}