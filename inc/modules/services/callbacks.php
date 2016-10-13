<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_services_settings_callback( $settings ) {
	$modulenow = 'services';
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return array( 'sanitized' => 1 );
	}

	$settings = array( 'sanitized' => 1 );

	$summary         = ! empty( $_POST['secupress_services_settings']['support_summary'] )     ? preg_replace( "@[\r\n]+@", ' ', strip_tags( wp_unslash( trim( html_entity_decode( $_POST['secupress_services_settings']['support_summary'], ENT_QUOTES ) ) ) ) ) : ''; // WPCS: CSRF ok.
	$description     = ! empty( $_POST['secupress_services_settings']['support_description'] ) ? str_replace( "\r\n", "\n", strip_tags( wp_unslash( trim( html_entity_decode( $_POST['secupress_services_settings']['support_description'], ENT_QUOTES ) ) ) ) )  : ''; // WPCS: CSRF ok.

	$esc_description = $description ? esc_html( $description ) : '';
	$esc_def_message = __( 'Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page', 'secupress' ) . "\n\n" .
	                   __( 'Please let us know how we will recognize the issue or can reproduce the issue. What is supposed to happen, and what is actually happening instead?', 'secupress' );
	$esc_def_message = esc_html( str_replace( "\r\n", "\n", strip_tags( trim( html_entity_decode( $esc_def_message, ENT_QUOTES ) ) ) ) );

	// Free plugin.
	if ( ! secupress_is_pro() ) {
		$message = sprintf(
			/** Translators: 1 is the plugin name, 2 is a link to the "plugin directory". */
			__( 'Oh, you use the Free version of %1$s! Support is handled on the %2$s. Thank you!', 'secupress' ),
			SECUPRESS_PLUGIN_NAME,
			'<a href="https://wordpress.org/support/plugin/secupress" target="_blank" aria-label="' . esc_attr__( 'Opens in a new tab or window', 'secupress' ) . '">' . __( 'plugin directory', 'secupress' ) . '</a>'
		);

		if ( $esc_description && $esc_def_message !== $esc_description ) {
			if ( $summary ) {
				$message .= '</strong><br/>' . __( 'By the way, here is your subject:', 'secupress' ) . '</p>';
				$message .= '<blockquote>' . esc_html( $summary ) . '</blockquote>';
				$message .= '<p>' . __( 'And your message:', 'secupress' ) . '</p>';
			} else {
				$message .= '</strong><br/>' . __( 'By the way, here is your message:', 'secupress' ) . '</p>';
			}

			$message .= '<blockquote>' . nl2br( $esc_description ) . '</blockquote>';
			$message .= '<p>' . __( '(you\'re welcome)', 'secupress' ) . '<strong>';
		}

		add_settings_error( 'general', 'free_support', $message );

		return $settings;
	}

	// Pro plugin.
	if ( $summary && $description && $esc_def_message !== $esc_description ) {
		/**
		 * Triggered when the user is asking for support.
		 *
		 * @since 1.0.6
		 *
		 * @param (string) $summary     A title. The value is not escaped.
		 * @param (string) $description A message. The value is not escaped.
		 */
		do_action( 'secupress.services.ask_for_support', $summary, $description );
	} elseif ( ! $summary ) {
		// The summary is missing.
		add_settings_error( 'general', 'no_summary', __( 'Could you please give a short summary of your problem?', 'secupress' ) );
	} elseif ( ! $description ) {
		// The message is missing.
		add_settings_error( 'general', 'no_description', __( 'Without any description, it will be difficult to solve your problem.', 'secupress' ) );
	} else {
		// The message is the default one.
		add_settings_error( 'general', 'default_description', __( 'I don\'t think this description can be of any help.', 'secupress' ) );
	}

	return $settings;
}
