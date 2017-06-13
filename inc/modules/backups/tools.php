<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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
