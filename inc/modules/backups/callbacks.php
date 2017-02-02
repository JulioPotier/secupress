<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_backups_settings_callback() {
	return array();
}
