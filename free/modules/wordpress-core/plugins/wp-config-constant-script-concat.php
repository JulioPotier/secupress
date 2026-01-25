<?php
/**
 * Module Name: Disallow Scripts & Styles Concatenation
 * Description: Set the constant <code>CONCATENATE_SCRIPTS</code> from the <code>wp-config.php</code> file to <code>false</code>.
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.plugins.activation', 'secupress_wpconfig_htaccess_disallow_script_concat_activation' );
/**
 * On module activation, remove the define.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_wpconfig_htaccess_disallow_script_concat_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	secupress_wpconfig_modules_activation( 'script_concat' );

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_script_concat_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_script_concat_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_script_concat_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'script_concat',
		'title'  => __( 'Scripts Concatenation', 'secupress' ),

	) );
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_script_concat_activation_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_script_concat_activation_file() {
	secupress_wpconfig_htaccess_disallow_script_concat_activation();
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_script_concat_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_script_concat_deactivate() {
	secupress_wpconfig_htaccess_disallow_script_concat_deactivation();
}


add_action( 'secupress.plugins.deactivation', 'secupress_wpconfig_htaccess_disallow_script_concat_deactivation' );
/**
 * On module deactivation, maybe put the constant back.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_wpconfig_htaccess_disallow_script_concat_deactivation() {
	secupress_wpconfig_modules_deactivation( 'script_concat' );
	secupress_remove_module_rules_or_notice( 'script_concat', __( 'Scripts Concatenation', 'secupress' ) );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_script_concat_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_script_concat_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'script_concat';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_script_concat_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_script_concat_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_script_concat_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Scripts Concatenation: get rules for apache.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (string)
 */
function secupress_script_concat_apache_rules() {
	$rules  = "<FilesMatch \"load-scripts\.php|load-styles\.php\">\n";
	$rules .= "	<IfModule !mod_authz_core.c>\n";
	$rules .= "		Order Allow,Deny\n";
	$rules .= "		Deny from all\n";
	$rules .= "	</IfModule>\n";
	$rules .= "	<IfModule mod_authz_core.c>\n";
	$rules .= "		Require all denied\n";
	$rules .= "	</IfModule>\n";
	$rules .= "</FilesMatch>\n";
	return $rules;
}


/**
 * Scripts Concatenation: get rules for iis7.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (string)
 */
function secupress_script_concat_iis7_rules() {
	$marker = 'script_concat';

	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "    <match url=\"load-scripts\.php|load-styles\.php\"/>\n";
	$rules .= "    <action type=\"CustomResponse\" statusCode=\"403\" ubStatusCode=\"0\" statusReason=\"Forbidden\" statusDescription=\"Access denied.\"/>\n";
	$rules .= "</rule>";

	return $rules;
}


/**
 * Scripts Concatenation: get rules for nginx.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (string)
 */
function secupress_script_concat_nginx_rules() {
	$marker = 'script_concat';

	$rules  = "
server {
	# BEGIN SecuPress $marker
	location ~ /(load-scripts|load-styles)\.php$ {
		deny all;
	}

	# END SecuPress
}";

	return trim( $rules );
}
