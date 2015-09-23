<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'profile_protect' );
$this->set_section_description( __( 'Your profile can contain sensitive data and is also used to change your password. Don\'t let anyone sneaking into it.', 'secupress' ) );
$this->add_section( __( 'Profile Settings Page Protection', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'profile_protect'


$this->add_field(
	__( 'Protect the profile page', 'secupress' ),
	array(
		'name'        => 'plugin_' . $plugin,
		'description' => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_' . $plugin,
			'value'        => 'profile_protect',
			'label'        => __( 'Yes, protect the profile pages', 'secupress' ),
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Yes, protect the profile pages', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-emaillink', 'block-plugin_' . $plugin ),
			'description'  => __( 'By using this protection, nobody can stalk into your profile page when you left your computer.', 'secupress' ),
		),
	)
);
