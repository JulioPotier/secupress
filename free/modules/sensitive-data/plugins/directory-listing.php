<?php
/**
 * Module Name: Directory Listing
 * Description: Disable files browsing.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activation', 'secupress_directory_listing_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_directory_listing_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_directory_listing_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_directory_listing_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_directory_listing_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	$edited = secupress_add_module_rules_or_notice( array(
		'rules'    => $rules,
		'marker'   => 'directory_listing',
		'iis_args' => array( 'node_types' => 'directoryBrowse' ),
		'title'    => __( 'Directory Listing', 'secupress' ),
	) );

	// For Apache: maybe remove previous `Options +Indexes`.
	if ( ! $edited || ! $is_apache ) {
		return;
	}

	$file_path = secupress_get_home_path() . '.htaccess';
	secupress_replace_content( $file_path, "/Options\s+\+Indexes\s*(?:\n|$)/", '' );
}


add_filter( 'secupress.plugins.activation.htaccess_content_before_write_rules', 'secupress_directory_listing_activation_remove_rule' );
/**
 * Filter the `.htaccess` file content before add new rules on activation: maybe remove previous `Options +Indexes`.
 * This filter will run on Apache, before `secupress_directory_listing_activation()`.
 *
 * @since 1.0
 *
 * @param (string) $file_content The file content.
 */
function secupress_directory_listing_activation_remove_rule( $file_content ) {
	// Maybe remove `Options +Indexes`.
	return preg_replace( "/Options\s+\+Indexes\s*(?:\n|$)/", '', $file_content );
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_directory_listing_activation_file' );
function secupress_directory_listing_activation_file() {
	secupress_directory_listing_activation();
	secupress_scanit( 'Directory_Listing', 3 );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_directory_listing_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_directory_listing_deactivate() {
	secupress_remove_module_rules_or_notice( 'directory_listing', __( 'Directory Listing', 'secupress' ) );
	secupress_scanit( 'Directory_Listing', 3 );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_directory_listing_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_directory_listing_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'directory_listing';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_directory_listing_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_directory_listing_iis7_rules(), 'node_types' => 'directoryBrowse' );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_directory_listing_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Directory Listing: get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_listing_apache_rules() {
	$rules  = "<IfModule mod_autoindex.c>\n";
	$rules .= "    Options -Indexes\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * Directory Listing: get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_listing_iis7_rules() {
	$marker = 'directory_listing';
	$rules  = '<directoryBrowse name="SecuPress ' . $marker . '" enabled="false" showFlags=""/>';

	return $rules;
}


/**
 * Directory Listing: get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_listing_nginx_rules() {
	$marker = 'directory_listing';
	$bases  = secupress_get_rewrite_bases();
	$base   = $bases['base'];

	$rules  = "
server {
	# BEGIN SecuPress $marker
	location $base {
		autoindex off;
	}
	# END SecuPress
}";

	return trim( $rules );
}
