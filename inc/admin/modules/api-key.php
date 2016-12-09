<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'secupress_display_apikey_options' );
$this->add_section( __( 'License Validation', 'secupress' ), array( 'with_save_button' => false ) );


$settings   = get_site_option( SECUPRESS_SETTINGS_SLUG );
$disabled   = is_array( $settings ) && ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) && ! empty( $settings['site_is_pro'] );
$attributes = array(
	'required'      => 'required',
	'aria-required' => 'true',
	'autocomplete'  => 'off',
);

if ( $disabled ) {
	$attributes['readonly'] = true;
}

$this->add_field( array(
	'title'        => __( 'E-mail Address', 'secupress' ),
	'label_for'    => 'consumer_email',
	'type'         => 'email',
	'attributes'   => $attributes,
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => _x( 'The one you used for your Pro account.', 'e-mail address', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'License Key', 'secupress' ),
	'label_for'    => 'consumer_key',
	'type'         => 'text',
	'attributes'   => $attributes,
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The license key obtained with your Pro account.', 'secupress' ),
		),
	),
) );


add_action( 'secupress.settings.after_section_secupress_display_apikey_options', 'secupress_apikey_fields_submit_button' );
/**
 * Print a warning message and a submit button to activate the license key.
 *
 * @since 1.0.5
 * @author Grégory Viguier
 *
 * @param (bool) $with_save_button True if a "Save All Changes" button will be printed.
 */
function secupress_apikey_fields_submit_button( $with_save_button ) {
	if ( $with_save_button ) {
		return;
	}

	$values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$label  = __( 'Activate the license', 'secupress' );

	if ( is_array( $values ) && ! empty( $values['consumer_email'] ) && ! empty( $values['consumer_key'] ) ) {
		if ( empty( $values['site_is_pro'] ) ) {
			echo '<p style="color:#CB234F">' . __( 'Your License Key is inactive or invalid.', 'secupress' ) . '</p>';
		} else {
			$label = __( 'Deactivate the license', 'secupress' );
		}
	}

	echo '<p class="submit"><button type="submit" class="secupress-button-primary" name="secupress_display_apikey_options_submit">' . $label . '</button></p>';
}
