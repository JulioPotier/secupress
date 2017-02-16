<?php
/**
 * Module Name: Directory Index
 * Description: Prevent <code>.html</code>/<code>.htm</code> files to be loaded before the <code>.php</code> one.
 * Main Module: file_system
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_directory_index_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_directory_index_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_directory_index_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_directory_index_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_directory_index_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'    => $rules,
		'marker'   => 'directory_index',
		'iis_args' => array( 'node_types' => 'defaultDocument' ),
		'title'    => __( 'Directory Index', 'secupress' ),
	) );
}


add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_directory_index_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_directory_index_deactivate() {
	secupress_remove_module_rules_or_notice( 'directory_index', __( 'Directory Index', 'secupress' ) );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_directory_index_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_directory_index_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'directory_index';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_directory_index_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_directory_index_iis7_rules(), 'node_types' => 'defaultDocument' );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_directory_index_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Directory Index: get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_index_apache_rules() {
	$rules  = "<IfModule mod_dir.c>\n";
	$rules .= "    DirectoryIndex index.php index.html index.htm index.cgi index.pl index.xhtml\n";
	$rules .= "</IfModule>\n";

	return $rules;
}


/**
 * Directory Index: get rules for iis7.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_index_iis7_rules() {
	$marker = 'directory_index';

	$rules  = "<defaultDocument name=\"SecuPress $marker\">\n";
	$rules .= "      <files>\n";
	$rules .= "        <remove value=\"index.php\" />\n";
	$rules .= "        <add value=\"index.php\" />\n";
	$rules .= "      </files>\n";
	$rules .= '    </defaultDocument>';

	return $rules;
}


/**
 * Directory Index: get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_directory_index_nginx_rules() {
	$marker = 'directory_index';

	$rules  = "
server {
	# BEGIN SecuPress $marker
	index index.php;
	# END SecuPress
}";

	return trim( $rules );
}
