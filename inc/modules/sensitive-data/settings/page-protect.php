<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'page_protect' );
$this->add_section( __( 'Page Protection', 'secupress' ) );


$this->add_field( array(
	'title'             => __( 'Protect the profile page', 'secupress' ),
	'description'       => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'profile' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'sensitive-data', 'profile-protect' ),
	'label'             => __( 'Yes, protect the profile page', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'By using this protection, nobody can access your profile page when you leave your computer.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => sprintf( __( 'Protect %s pages', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
	'description'       => __( 'Protect those pages once your settings are done.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'settings' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'sensitive-data', 'options-protect' ),
	'label'             => __( 'Yes, protect the settings pages', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'By using this protection, nobody can access the settings page when you leave your computer.', 'secupress' ),
		),
	),
) );
