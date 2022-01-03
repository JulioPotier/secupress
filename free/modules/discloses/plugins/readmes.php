<?php
/**
 * Module Name: Protect Readme Files
 * Description: Deny access to all <code>readme</code> and <code>changelog</code> files.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activation', 'secupress_protect_readmes_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_protect_readmes_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_protect_readmes_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_protect_readmes_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_protect_readmes_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'readme_discloses',
		'title'  => __( 'Protect Readme Files', 'secupress' ),
	) );
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_protect_readmes_activation_file' );
function secupress_protect_readmes_activation_file() {
	secupress_protect_readmes_activation();
	secupress_scanit( 'Readme_Discloses', 3 );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_protect_readmes_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_protect_readmes_deactivate() {
	secupress_remove_module_rules_or_notice( 'readme_discloses', __( 'Protect Readme Files', 'secupress' ) );
	secupress_scanit( 'Readme_Discloses', 3 );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_protect_readmes_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_protect_readmes_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'readme_discloses';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_protect_readmes_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_protect_readmes_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_protect_readmes_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Protect Readme Files: get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_protect_readmes_apache_rules() {
	$bases   = secupress_get_rewrite_bases();
	$base    = $bases['base'];
	$pattern = '^' . $bases['site_from'] . '(.*/)?(readme|changelog|debug)\.(txt|md|html|log)$';

	$rules  = "<IfModule mod_rewrite.c>\n";
	$rules .= "    RewriteEngine On\n";
	$rules .= "    RewriteBase $base\n";
	$rules .= "    RewriteRule $pattern - [R=404,L,NC]\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * Protect Readme Files: get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_protect_readmes_iis7_rules() {
	$marker  = 'readme_discloses';
	$spaces  = str_repeat( ' ', 8 );
	$bases   = secupress_get_rewrite_bases();
	$pattern = '^' . $bases['site_from'] . '(.*/)?(readme|changelog|debug)\.(txt|md|html|log)$';

	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "$spaces  <match url=\"$pattern\"/ ignoreCase=\"true\">\n";
	$rules .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
	$rules .= "$spaces</rule>";

	return $rules;
}


/**
 * Protect Readme Files: get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_protect_readmes_nginx_rules() {
	$marker  = 'readme_discloses';
	$bases   = secupress_get_rewrite_bases();
	$pattern = '^' . $bases['site_from'] . '(.+/)?(readme|changelog|debug)\.(txt|md|html|log)$';

	// - http://nginx.org/en/docs/http/ngx_http_core_module.html#location
	$rules  = "
server {
	# BEGIN SecuPress $marker
	location ~* $pattern {
		return 404;
	}
	# END SecuPress
}";

	return trim( $rules );
}
