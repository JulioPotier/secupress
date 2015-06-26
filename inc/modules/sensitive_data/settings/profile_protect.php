<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

$sectionnow = 'profile_protect';
$pluginnow = 'profile_protect';

secupress_add_settings_section( __( 'Profile Settings Page Protection', 'secupress' ) );


	secupress_add_settings_field(
		__( 'Protect the profile page', 'secupress' ),
		array(	'description' => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ),
				'name' => 'plugin_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_' . $pluginnow,
				'value'			=> 'profile_protect',
				'label'			=> __( 'Yes, protect the profile pages', 'secupress' ),
				'label_for'		=> 'plugin_' . $pluginnow,
				'label_screen'	=> __( 'Yes, protect the profile pages', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_' . $pluginnow,
				'class'	=> array( 'hidden', 'block-hidden', 'block-emaillink', 'block-' . 'plugin_' . $pluginnow ),
				'description'  => __( 'By using this protection, nobody can stalk into your profile page when you left your computer.', 'secupress' ),
			),
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );
