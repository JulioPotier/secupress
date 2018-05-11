<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

// Add the form manually.
add_action( 'secupress.settings.before_section_secupress_display_apikey_options', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_secupress_display_apikey_options', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'secupress_display_apikey_options' );
$this->add_section( __( 'License Validation', 'secupress' ) );

add_filter( 'secupress.settings.section-secupress_display_apikey_options.submit_button_args', 'secupress_submit_button_title_for_secupress_display_apikey_options' );;
/**
 * Filter the submit button for the licence.
 *
 * @since 1.4.3
 *
 * @return (array) $args
 * @author Julio Potier
 * @param (array) $args Contains the attributes and stuff to create a submit button.
 **/
function secupress_submit_button_title_for_secupress_display_apikey_options( $args ) {
	$values = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$label  = __( 'Activate the license', 'secupress' );
	$before = '';

	if ( is_array( $values ) && ! empty( $values['consumer_email'] ) && ! empty( $values['consumer_key'] ) ) {
		if ( empty( $values['site_is_pro'] ) ) {
			$before = '<p style="color:#CB234F">' . __( 'Your License Key is inactive or invalid.', 'secupress' ) . '</p>';
		} else {
			$label  = __( 'Deactivate the license', 'secupress' );
		}
	}

	$args['before'] = $before;
	$args['label']  = $label;

	return $args;
}

$settings   = get_site_option( SECUPRESS_SETTINGS_SLUG );
$disabled   = is_array( $settings ) && ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) && ! empty( $settings['site_is_pro'] );
$value      = false;
$attributes = array(
	'required'      => 'required',
	'aria-required' => 'true',
	'autocomplete'  => 'off',
);
if ( $disabled ) {
	$attributes['readonly'] = true;
	$value = str_repeat( '&bull;', 22 );
}

$this->add_field( array(
	'title'        => __( 'E-mail Address', 'secupress' ),
	'label_for'    => 'consumer_email',
	'type'         => 'email',
	'attributes'   => $attributes,
	'value'        => defined( 'SECUPRESS_API_EMAIL' ) ? esc_attr( SECUPRESS_API_EMAIL ) : secupress_get_consumer_email(),
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
	'value'        => $value,
	'value'        => defined( 'SECUPRESS_API_KEY' ) ? esc_attr( SECUPRESS_API_KEY ) : $value,
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The license key obtained with your Pro account.', 'secupress' ),
		),
	),
) );


// add_action( 'secupress.settings.after_section_secupress_display_apikey_options', 'secupress_apikey_fields_submit_button', 9 );
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
