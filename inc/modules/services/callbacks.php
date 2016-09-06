<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_services_settings_callback( $settings ) {
	$modulenow = 'services';
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}

	$settings = array( 'sanitized' => 1 );

	if ( ! secupress_is_pro() ) {
		$message = __( 'During the test phase, the support is done by sending a manual email on <b>support@secupress.me</b>. Thank you!', 'secupress' ); // ////.
		if ( ! empty( $_POST['secupress_services_settings']['support_description'] ) ) { // WPCS: CSRF ok.
			$message .= '</strong><br/>' . __( 'By the way, here is your message:', 'secupress' ) . '</p>';
			$message .= '<blockquote>' . nl2br( esc_html( wp_unslash( trim( $_POST['secupress_services_settings']['support_description'] ) ) ) ) . '</blockquote>'; // WPCS: CSRF ok.
			$message .= '<p>' . __( '(you\'re welcome)', 'secupress' ) . '<strong>';
		}
		add_settings_error( 'general', 'free_support', $message );
		return $settings;
	}

	// //// Send support request here.

	return $settings;
}
