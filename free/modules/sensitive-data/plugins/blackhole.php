<?php
/**
 * Module Name: Blackhole
 * Description: Catch bots that don't respect your <code>robots.txt</code> rules.
 * Main Module: sensitive_data
 * Author: SecuPress
 * Version: 2.3.19
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_blackhole_activate_write_robotstxt' );
add_action( 'secupress.modules.activation', 'secupress_blackhole_activate_write_robotstxt' );
/**
 * Add our content to the robots.txt if does exist
 *
 * @author Julio Potier
 * @since 2.2.6
 */
function secupress_blackhole_activate_write_robotstxt() {
	$filesystem = secupress_get_filesystem();
	$filename   = ABSPATH . 'robots.txt';

	if ( ! file_exists( $filename ) ) { // We do not create it, the hook is enough
		return;
	}
	$contents   = $filesystem->get_contents( $filename );
	$contents   = secupress_blackhole_robotstxt_content( $contents );
	$filesystem->put_contents( $filename, $contents );
}

add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_blackhole_deactivate_write_robotstxt' );
add_action( 'secupress.modules.deactivation', 'secupress_blackhole_deactivate_write_robotstxt' );
/**
 * Add our content to the robots.txt if does exist
 *
 * @author Julio Potier
 * @since 2.2.6
 */
function secupress_blackhole_deactivate_write_robotstxt() {
	$filesystem = secupress_get_filesystem();
	$filename   = ABSPATH . 'robots.txt';

	if ( ! file_exists( $filename ) ) { // We do not create it, the hook it enough
		return;
	}
	$contents   = $filesystem->get_contents( $filename );
	$dirname    = secupress_get_hashed_folder_name( basename( __FILE__, '.php' ) );

	if ( false !== strpos( $contents, "User-agent: *\nDisallow: $dirname\n" ) ) {
		$contents  = str_replace( "User-agent: *\nDisallow: $dirname\n", "User-agent: *\n", $contents );
		$filesystem->put_contents( $filename, $contents );
	}
}

add_filter( 'robots_txt', 'secupress_blackhole_robotstxt_content', 20 );
/**
 * Add forbidden URI in `robots.txt` file.
 *
 * @since 2.3.19 remove the conditions because if this is a real file, we can't run that, no big deal, so remove param $forced
 * @since 2.2.6 Add the rule on line 1 if not present
 * @author Julio Potier
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $output File content.
 *
 * @return (string) File content.
 */
function secupress_blackhole_robotstxt_content( $output ) {
	$dirname = secupress_get_hashed_folder_name( basename( __FILE__, '.php' ) );

	if ( false !== strpos( $output, "User-agent: *\n" ) ) {
		$output  = str_replace( "User-agent: *\n", "User-agent: *\nDisallow: $dirname\n", $output );
	} else {
		$output = "User-agent: *\nDisallow: $dirname\n\n" . $output;
	}

	return $output;
}