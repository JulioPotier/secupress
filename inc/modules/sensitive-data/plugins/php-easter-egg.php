<?php
/**
 * Module Name: PHP Disclosure
 * Description: Protect against PHP Easter Egg.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activation', 'secupress_php_disclosure_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_php_disclosure_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_php_disclosure_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_php_disclosure_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_php_disclosure_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'php_disclosure',
		'title'  => __( 'PHP Disclosure', 'secupress' ),
	) );
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_php_disclosure_activation_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 */
function secupress_php_disclosure_activation_file() {
	secupress_php_disclosure_activation();
	secupress_scanit( 'PHP_Disclosure', 3 );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_php_disclosure_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_php_disclosure_deactivate() {
	secupress_remove_module_rules_or_notice( 'php_disclosure', __( 'PHP Disclosure', 'secupress' ) );
	secupress_scanit( 'PHP_Disclosure', 3 );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_php_disclosure_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_php_disclosure_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'php_disclosure';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_php_disclosure_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_php_disclosure_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_php_disclosure_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * PHP Disclosure: get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_php_disclosure_apache_rules() {
	$rules  = "<IfModule mod_rewrite.c>\n";
	$rules .= "    RewriteEngine On\n";
	$rules .= "    RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC]\n";
	$rules .= "    RewriteRule .* - [F]\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * PHP Disclosure: get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_php_disclosure_iis7_rules() {
	$marker = 'php_disclosure';
	$spaces = str_repeat( ' ', 8 );

	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "$spaces  <match url=\".*\"/>\n";
	$rules .= "$spaces  <conditions>\n";
	$rules .= "$spaces    <add input=\"{URL}\" pattern=\"\=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\" ignoreCase=\"true\"/>\n";
	$rules .= "$spaces  </conditions>\n";
	$rules .= "$spaces  <action type=\"AbortRequest\"/>\n";
	$rules .= "$spaces</rule>";

	return $rules;
}


/**
 * PHP Disclosure: get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_php_disclosure_nginx_rules() {
	$marker = 'php_disclosure';

	$rules  = "
server {
	# BEGIN SecuPress $marker
	location / {
		if ( \$query_string ~* \"\=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\" ) {
			deny all;
		}
	}
	# END SecuPress
}";

	return trim( $rules );
}
