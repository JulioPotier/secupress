<?php
/**
 * Module Name: Bad File Extensions
 * Description: Forbid access to files with bad extension in the uploads folder.
 * Main Module: file_system
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** ----------------------------------------------------------------------------------------------*/

add_action( 'secupress.modules.activation', 'secupress_bad_file_extensions_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_bad_file_extensions_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_bad_file_extensions_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_bad_file_extensions_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_bad_file_extensions_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'bad_file_extensions',
		'title'  => __( 'Bad File Extensions', 'secupress' ),
	) );
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_file_extensions_activation_file' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 2.0
 */
function secupress_bad_file_extensions_activation_file() {
	secupress_bad_file_extensions_activation();
	secupress_scanit_async( 'Bad_File_Extensions', 3 );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_file_extensions_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 2.0 Use secupress_scanit_async
 * @since 1.0
 */
function secupress_bad_file_extensions_deactivate() {
	secupress_remove_module_rules_or_notice( 'bad_file_extensions', __( 'Bad File Extensions', 'secupress' ) );
	secupress_scanit_async( 'Bad_File_Extensions', 3 );
}


add_filter( 'secupress.pro.plugins.activation.write_rules', 'secupress_bad_file_extensions_plugin_activate', 10, 2 );
/**
 * On SecuPress Pro activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_bad_file_extensions_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'bad_file_extensions';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_bad_file_extensions_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_bad_file_extensions_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_bad_file_extensions_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Get a regex pattern matching the file extensions.
 *
 * @since 2.0 revamp
 * @since 1.0
 *
 * @return (string)
 */
function secupress_bad_file_extensions_get_regex_pattern() {
	$bases      = secupress_get_rewrite_bases();
	$abspath    = wp_normalize_path( ABSPATH );

	$media_url  = wp_upload_dir( null, false );
	$media_url  = wp_normalize_path( trailingslashit( $media_url['basedir'] ) );
	$pos        = strpos( $media_url, $abspath );
	$media_url  = substr( $media_url, $pos + strlen( $abspath ) );
	$media_url  = $bases['home_from'] . $media_url;
	$bases      = secupress_get_rewrite_bases();
	$abspath    = wp_normalize_path( ABSPATH );

	$media_url  = wp_upload_dir( null, false );
	$media_url  = wp_normalize_path( trailingslashit( $media_url['basedir'] ) );
	$media_url  = str_replace( $abspath, '', $media_url ); // 'wp-content/uploads/'$media_url  = $bases['home_from'] . $media_url;

	$extensions = secupress_bad_file_extensions_get_forbidden_extensions();
	$extensions = implode( '#//#', $extensions );
	$extensions = preg_quote( $extensions );
	$extensions = str_replace( preg_quote( '#//#' ), '|', $extensions );

	return "^{$bases['site_from']}{$media_url}.*\.($extensions)$";
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_bad_file_extensions_apache_rules() {
	$bases   = secupress_get_rewrite_bases();
	$base    = $bases['base'];
	$pattern = secupress_bad_file_extensions_get_regex_pattern();

	$rules  = "<IfModule mod_rewrite.c>\n";
	$rules .= "    RewriteEngine On\n";
	$rules .= "    RewriteBase $base\n";
	$rules .= "    RewriteRule $pattern - [R=404,L,NC]\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * Get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_bad_file_extensions_iis7_rules() {
	$marker  = 'bad_file_extensions';
	$spaces  = str_repeat( ' ', 8 );
	$pattern = secupress_bad_file_extensions_get_regex_pattern();

	$rules   = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules  .= "$spaces  <match url=\"$pattern\" ignoreCase=\"true\"/>\n";
	$rules  .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
	$rules  .= "$spaces</rule>";

	return $rules;
}


/**
 * Get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_bad_file_extensions_nginx_rules() {
	$marker  = 'bad_file_extensions';
	$pattern = secupress_bad_file_extensions_get_regex_pattern();

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
