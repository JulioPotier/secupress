<?php
/**
 * Module Name: PHP Version Disclosure
 * Description: Unset the header <em>X-Powered-By</em> to avoid leaking sensitive information.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 1.1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** IN CASE THE REWRITE RULES DON'T WORK ======================================================== */
/** --------------------------------------------------------------------------------------------- */

if ( ! headers_sent() ) {
	header_remove( 'X-Powered-By' );
}


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_no_x_powered_by_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_no_x_powered_by_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_no_x_powered_by_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_no_x_powered_by_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_no_x_powered_by_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'    => $rules,
		'marker'   => 'no_x_powered_by',
		'iis_args' => array(
			'path'      => 'httpProtocol/customHeaders',
			'attribute' => 'id',
		),
		'title'    => __( 'PHP Version Disclosure', 'secupress' ),
	) );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_no_x_powered_by_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_no_x_powered_by_deactivate() {
	secupress_remove_module_rules_or_notice( 'no_x_powered_by', __( 'PHP Version Disclosure', 'secupress' ) );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_no_x_powered_by_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_no_x_powered_by_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'no_x_powered_by';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_no_x_powered_by_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array(
			'nodes_string' => secupress_no_x_powered_by_iis7_rules(),
			'path'         => 'httpProtocol/customHeaders',
			'attribute'    => 'id',
		);
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_no_x_powered_by_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * No X-Powered-By: get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_no_x_powered_by_apache_rules() {
	$rules  = "ServerSignature Off\n";
	$rules  = "<IfModule mod_headers.c>\n";
	$rules .= "    Header unset X-Powered-By\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * No X-Powered-By: get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_no_x_powered_by_iis7_rules() {
	$marker = 'no_x_powered_by';
	$spaces = str_repeat( ' ', 8 );

	// - https://www.iis.net/configreference/system.webserver/httpprotocol/customheaders
	// - https://stackoverflow.com/questions/1178831/remove-server-response-header-iis7
	$rules  = "<remove name=\"X-AspNet-Version\" id=\"SecuPress $marker 1\"/>\n";
	$rules .= "$spaces<remove name=\"X-AspNetMvc-Version\" id=\"SecuPress $marker 2\"/>\n";
	$rules .= "$spaces<remove name=\"X-Powered-By\" id=\"SecuPress $marker 3\"/>";

	return $rules;
}


/**
 * No X-Powered-By: get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_no_x_powered_by_nginx_rules() {
	$marker = 'no_x_powered_by';

	// - http://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
	$rules  = "
server {
	# BEGIN SecuPress $marker
	server_tokens off;
	proxy_hide_header X-Powered-By;
	fastcgi_hide_header X-Powered-By;
	# END SecuPress
}";

	return trim( $rules );
}
