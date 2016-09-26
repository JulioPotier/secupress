<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'secupress_display_apikey_options' );
$this->add_section( __( 'License Validation', 'secupress' ) );


$this->add_field( array(
	'title'        => __( 'E-mail Address', 'secupress' ),
	'label_for'    => 'consumer_email',
	'type'         => 'email',
	'attributes'   => array(
		'required'      => 'required',
		'aria-required' => 'true',
	),
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
	'attributes'   => array(
		'required'      => 'required',
		'aria-required' => 'true',
		'autocomplete'  => 'off',
	),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The license key obtained with your Pro account.', 'secupress' ),
		),
	),
) );
