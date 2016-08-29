<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_backups_settings_callback( $settings ) {
	$locations = secupress_backups_storage_labels();
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	if ( ! isset( $settings['backups-storage_location'] ) || ! secupress_is_pro() || ! isset( $locations[ $settings['backups-storage_location'] ] ) ) {
		$settings['backups-storage_location'] = null;
	}

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

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
		'dropbox'   => __( 'Dropbox', 'secupress' ),
		// 'amazons3'  => __( 'Amazon S3', 'secupress' ), ////
		// 'rackspace' => __( 'Rackspace Cloud', 'secupress' ), ////
	);
}
