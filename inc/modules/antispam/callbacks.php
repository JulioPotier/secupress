<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_antispam_settings_callback() {
	return array();
}
