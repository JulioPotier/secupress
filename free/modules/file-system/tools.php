<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get file extensions that are allowed in the uploads folder.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (array)
 */
function secupress_get_allowed_extensions() {
	$exts             = get_allowed_mime_types();
	$exts['htm|html'] = 1;
	$exts['js']       = 1;
	$exts['php']      = 1; // allow PHP, only the allowed files will be loaded.
	$exts['ai']       = 1;
	$exts['eps']      = 1;
	$exts['ttf']      = 1;
	$exts['otf']      = 1;
	$exts['ott']      = 1;
	$exts['woff']     = 1;
	$exts['woff2']    = 1;
	$exts['eot']      = 1;
	$exts['svg']      = 1;
	$exts['md']       = 1;
	$exts['log']      = 1;
	/**
	* Filter the allowed extensions for the module "bad file extentions"
	* @param (string) $exts
	*/
	$exts             = apply_filters( 'secupress.plugins.bad_file_extensions.allowed_extensions', $exts );
	$exts             = array_keys( $exts );
	return $exts;
}