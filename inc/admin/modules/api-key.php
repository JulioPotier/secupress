<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$description = implode( "<br/>\n", array(
	__( 'Some features need a free account to be created, because they are linked to services provided with our servers.', 'secupress' ),
	sprintf(
		/* translators: %s is a "Buy a licence" link */
		__( 'You can %s, or only <strong>enter your email address</strong> below and <strong>save</strong> to get your free account.', 'secupress' ),
		'<a href="#" target="_blank">' . __( 'buy a licence to unlock all the features', 'secupress' ) . '</a>'// ////.
	),
) );


$this->set_current_section( 'secupress_display_apikey_options' );
$this->set_section_description( $description );
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
			'description' => __( 'The one you used for your Pro account. Or provide a new one to create a free account.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'API Key', 'secupress' ),
	'label_for'    => 'consumer_key',
	'type'         => 'text',
	'attributes'   => array(
	'autocomplete' => 'off',
	),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => __( 'The API key obtained with your Pro account. Leave empty and save to get a free account.', 'secupress' ),
		),
	),
) );
