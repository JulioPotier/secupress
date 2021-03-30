<?php
/**
 * Module Name: WordPress Version Disclosure
 * Description: Remove the WP generator meta tag, the WP version from the script tags, the WP version from the style tags, and deny access to the <code>readme.html</code> file.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activation', 'secupress_wp_version_activation' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 1.0
 */
function secupress_wp_version_activation() {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache ) {
		$rules = secupress_wp_version_apache_rules();
	}
	// IIS7.
	elseif ( $is_iis7 ) {
		$rules = secupress_wp_version_iis7_rules();
	}
	// Nginx.
	elseif ( $is_nginx ) {
		$rules = secupress_wp_version_nginx_rules();
	}
	// Not supported.
	else {
		$rules = '';
	}

	secupress_add_module_rules_or_notice( array(
		'rules'  => $rules,
		'marker' => 'wp_version',
		'title'  => __( 'WordPress Version Disclosure', 'secupress' ),
	) );
}


add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wp_version_activation' );
function secupress_wp_version_activation_file() {
	secupress_wp_version_activation();
	secupress_scanit_async( 'Discloses', 3 );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_wp_version_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 */
function secupress_wp_version_deactivate() {
	secupress_remove_module_rules_or_notice( 'wp_version', __( 'WordPress Version Disclosure', 'secupress' ) );
	secupress_scanit_async( 'Discloses', 3 );
}


add_filter( 'secupress.plugins.activation.write_rules', 'secupress_wp_version_plugin_activate', 10, 2 );
/**
 * On SecuPress activation, add the rules to the list of the rules to write.
 *
 * @since 1.0
 *
 * @param (array) $rules Other rules to write.
 *
 * @return (array) Rules to write.
 */
function secupress_wp_version_plugin_activate( $rules ) {
	global $is_apache, $is_nginx, $is_iis7;
	$marker = 'wp_version';

	if ( $is_apache ) {
		$rules[ $marker ] = secupress_wp_version_apache_rules();
	} elseif ( $is_iis7 ) {
		$rules[ $marker ] = array( 'nodes_string' => secupress_wp_version_iis7_rules() );
	} elseif ( $is_nginx ) {
		$rules[ $marker ] = secupress_wp_version_nginx_rules();
	}

	return $rules;
}


/** --------------------------------------------------------------------------------------------- */
/** README.HTML ================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get rules for apache.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_wp_version_apache_rules() {
	$bases   = secupress_get_rewrite_bases();
	$base    = $bases['base'];
	$pattern = '^' . $bases['site_from'] . 'readme\.html$';

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
function secupress_wp_version_iis7_rules() {
	$marker  = 'wp_version';
	$spaces  = str_repeat( ' ', 8 );
	$bases   = secupress_get_rewrite_bases();
	$pattern = '^' . $bases['site_from'] . 'readme\.html$';

	$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules .= "$spaces  <match url=\"$pattern\"/ ignoreCase=\"true\">\n";
	$rules .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
	$rules .= "$spaces</rule>";

	return $rules;
}


/**
 * Get rules for nginx.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_wp_version_nginx_rules() {
	$marker  = 'wp_version';
	$bases   = secupress_get_rewrite_bases();
	$pattern = $bases['site_from'] . 'readme.html';

	// - http://nginx.org/en/docs/http/ngx_http_core_module.html#location
	$rules  = "
server {
	# BEGIN SecuPress $marker
	location $pattern {
		return 404;
	}
	# END SecuPress
}";

	return trim( $rules );
}


/** --------------------------------------------------------------------------------------------- */
/** GENERATOR META TAG ========================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Remove the generator meta tag.
 *
 * @since 1.0
 */
foreach ( array( 'wp_head', 'rss2_head', 'commentsrss2_head', 'rss_head', 'rdf_header', 'atom_head', 'comments_atom_head', 'opml_head', 'app_head' ) as $generator_action ) {
	remove_action( $generator_action, 'the_generator' );
}


/**
 * Just to be sure, bloat its value: some plugin/theme may add the tag back.
 *
 * @since 1.0
 */
add_filter( 'the_generator', '__return_empty_string', PHP_INT_MAX );


/** --------------------------------------------------------------------------------------------- */
/** SCRIPTS AND STYLES ========================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'script_loader_src', 'secupress_replace_wp_version_in_src', PHP_INT_MAX );
add_filter( 'style_loader_src',  'secupress_replace_wp_version_in_src', PHP_INT_MAX );
/**
 * Replace the WordPress version with a fake version in script and style src.
 *
 * @param (string) $src A content containing the string `ver={$wp_version}`.
 *
 * @return (string)
 */
function secupress_replace_wp_version_in_src( $src ) {
	$ver  = get_bloginfo( 'version' );
	$hash = secupress_generate_hash( $ver );

	return str_replace( 'ver=' . $ver, 'ver=' . $hash, $src );
}

add_filter( 'update_footer', 'secupress_replace_wp_version_in_footer', 11 );
/**
 * Remove the WP version number in footer
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $footer
 * @return (string) $footer
 **/
function secupress_replace_wp_version_in_footer( $footer ) {
	if ( ! current_user_can( 'update_core' ) ) {
		$footer = str_replace( sprintf( __( 'Version %s' ), get_bloginfo( 'version', 'display' ) ), __( 'Powered by WordPress', 'secupress' ), $footer );
	}
	return $footer;
}
