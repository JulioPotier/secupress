<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Used to flush the .htaccess file
 *
 * @since 1.0
 *
 * @param bool $force (default: false)
 * @return void
 */
function flush_secupress_htaccess( $force = false )
{
	if ( ! $GLOBALS['is_apache'] ) {
		return;
	}

	$rules = '';
	$htaccess_file = get_home_path() . '.htaccess';

	if ( is_writable( $htaccess_file ) ) {
		// Get content of .htaccess file
		$ftmp = file_get_contents( $htaccess_file );

		// Remove the WP Rocket marker
		$ftmp = preg_replace( '/# BEGIN SecuPress(.*)# END SecuPress/isU', '', $ftmp );

		// Remove empty spacings
		$ftmp = str_replace( "\n\n" , "\n" , $ftmp );

		if ( $force === false ) {
			$rules = get_secupress_htaccess_marker();
		}

		// Update the .htacces file
		rocket_put_content( $htaccess_file, $rules . $ftmp );
	}
}

/**
 * Return the markers for htacces rules
 *
 * @since 1.0
 *
 * @return string $marker Rules that will be printed
 */
function get_secupress_htaccess_marker()
{
	// Recreate WP Rocket marker
	$marker  = '# BEGIN SecuPress v' . SECUPRESS_VERSION . PHP_EOL;
	////
	$marker .= '# END SecuPress' . PHP_EOL;

	/**
	 * Filter rules added by SecuPress in .htaccess
	 *
	 * @since 1.0
	 *
	 * @param string $marker The content of all rules
	*/
	$marker = apply_filters( 'secupress_htaccess_marker', $marker );

	return $marker;
}
