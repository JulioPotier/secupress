<?php
/**
 * Module Name: Protect Readme Disclosures
 * Description: Deny access to all <code>readme</code>, <code>changelog</code> and <code>debug</code> files.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVATION / DEACTIVATION =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_readme_discloses_activate' );
add_filter( 'secupress.plugins.activation.write_rules',                             'secupress_readme_discloses_activate' );
/**
 * On module activation, maybe write the rules.
 *
 * @since 2.2.6 
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_readme_discloses_activate() {
	$marker = 'readme_discloses';
	$rules  = [];

	$rules[ $marker ] = call_user_func( secupress_get_function_name_by_server_type( 'secupress_readme_discloses_rules_for_' ) );

	secupress_add_module_rules_or_notice( [
		'marker' => $marker,
		'rules'  => $rules[ $marker ],
		'title'  => esc_html__( 'Protect Readme Files', 'secupress' ),
	] );

	secupress_scanit( $marker, 3 );

	return $rules;
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_readme_discloses_deactivate' );
/**
 * On module deactivation, maybe remove rewrite rules from the `.htaccess`/`web.config` file.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_readme_discloses_deactivate() {
	secupress_remove_module_rules_or_notice( 'readme_discloses', __( 'Protect Readme Files', 'secupress' ) );
	secupress_scanit( 'readme_discloses', 3 );
}

/** --------------------------------------------------------------------------------------------- */
/** RULES ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Returns the regex for txt files that should not be read.
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $base
 * 
 * @return (string)
 */
function secupress_readme_discloses_get_pattern( $base ) {
	return '^' . $base . '(.*/)?(readme|changelog|debug)\.(txt|md|log|html?)$';
}

/**
 * Get rules for apache.
 *
 * @since 2.2.6 Custom 404
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_readme_discloses_rules_for_apache() {
	$bases   = secupress_get_rewrite_bases();
	$base    = $bases['base'];
	$pattern = secupress_readme_discloses_get_pattern( $bases['site_from'] ) . ' [NC]';

	$rules   = "<IfModule mod_rewrite.c>\n";
	$rules  .= "    RewriteEngine On\n";
	$rules  .= "    RewriteBase $base\n";
	$rules  .= "    RewriteRule ^ - [E=REDIRECT_PHP404:0]\n";
	$rules  .= "\n";
	$rules  .= "    RewriteCond %{REQUEST_URI} $pattern\n";
	$rules  .= "    RewriteRule ^ - [E=REDIRECT_PHP404:files]\n";
	$rules  .= "\n";
	$rules  .= "    RewriteCond %{ENV:REDIRECT_PHP404} !=0\n";
	$rules  .= "    " . secupress_get_404_rule_for_rewrites() . "\n";
	$rules  .= "</IfModule>\n";

	return $rules;
}


/**
 * Get rules for iis7.
 *
 * @since 2.2.6 Custom 404
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_readme_discloses_rules_for_iis7() {
	$marker  = 'readme_discloses';
	$bases   = secupress_get_rewrite_bases();
	$pattern = secupress_readme_discloses_get_pattern( $bases['site_from'] );
	$path    = str_replace( ABSPATH, '', SECUPRESS_INC_PATH );

	$rules   = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
	$rules  .= "    <match url=\"$pattern\"/ ignoreCase=\"true\">\n";
	$rules  .= "    <serverVariables>\n";
    $rules  .= "    	<set name=\"REDIRECT_PHP404\" value=\"files\" />\n";
    $rules  .= "    </serverVariables>\n";
    $rules  .= "    " . secupress_get_404_rule_for_rewrites() . "\n";
	$rules  .= "</rule>\n";

	return $rules;
}

/**
 * Get rules for nginx.
 *
 * @since 2.2.6 Custom 404
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_readme_discloses_rules_for_nginx() {
	$marker  = 'readme_discloses';
	$bases   = secupress_get_rewrite_bases();
	$pattern = secupress_readme_discloses_get_pattern( $bases['site_from'] );
	$path    = str_replace( ABSPATH, '', SECUPRESS_INC_PATH );
	$rule404 = secupress_get_404_rule_for_rewrites();
	$rules   = "
server {
	# BEGIN SecuPress {$marker}
	location ~* {$pattern} {
		set $"."REDIRECT_PHP404 \"files\";
		{$rule404}
	}
	# END SecuPress
}";

	return trim( $rules );
}
