<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'page_protect' );
$this->add_section( __( 'Settings Pages Protection', 'secupress' )/*, array( 'with_roles' => true )*/ );


$plugin = $this->get_current_plugin(); // 'page_protect'


$this->add_field(
	__( 'Protect the profile page', 'secupress' ),
	array(
		'name'        => 'profile_protect_' . $plugin,
		'description' => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'profile_protect_' . $plugin,
			'label'        => __( 'Yes, protect the profile pages', 'secupress' ),
			'label_for'    => 'profile_protect_' . $plugin,
			'label_screen' => __( 'Yes, protect the profile pages', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'profile_protect_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-profile_protect_' . $plugin ),
			'description'  => __( 'By using this protection, nobody can stalk into your profile page when you left your computer.', 'secupress' ),
		),
	)
);

$this->add_field(
	sprintf( __( 'Protect %s settings page', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
	array(	'description' => __( 'We recommand to protect the settings page once your settings are done.', 'secupress' ),
			'name' => 'settings_protect_' . $plugin,
		),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'settings_protect_' . $plugin,
			'label'        => __( 'Yes, protect the settings pages', 'secupress' ),
			'label_for'    => 'settings_protect_' . $plugin,
			'label_screen' => __( 'Yes, protect the settings pages', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'settings_protect_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-settings_protect_' . $plugin ),
			'description'  => __( 'By using this protection, nobody can stalk into the settings page when you left your computer.', 'secupress' ),
		),
	)
);
