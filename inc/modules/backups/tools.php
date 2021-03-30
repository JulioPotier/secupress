<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Return the values/labels used for the backups storage setting.
 *
 * @since 1.0
 *
 * @return (array) An array with back types as keys and labels as values.
 */
function secupress_backups_storage_labels() {
	return array(
		'local'     => __( 'Local', 'secupress' ),
		// 'dropbox'   => __( 'Dropbox', 'secupress' ), ////
		// 'amazons3'  => __( 'Amazon S3', 'secupress' ), ////
		// 'rackspace' => __( 'Rackspace Cloud', 'secupress' ), ////
	);
}

/**
 * Get backups parent folder path.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (bool) $relative Set to true to get the path relative to the site's root.
 *
 * @return (string) The absolute (or relative) path to the backups parent folder. The path has a trailing slash.
 */
function secupress_get_parent_backups_path( $relative = false ) {
	static $abs_path;
	static $rel_path;

	if ( ! isset( $abs_path ) ) {
		$abs_path = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/backups/';
		$rel_path = str_replace( rtrim( wp_normalize_path( ABSPATH ), '/' ), '', $abs_path );
	}

	return $relative ? $rel_path : $abs_path;
}
