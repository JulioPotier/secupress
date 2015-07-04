<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

$sectionnow = 'page_protect';
$pluginnow = 'page_protect';

secupress_add_settings_section( __( 'Settings Pages Protection', 'secupress' )/*, array( 'with_roles' => true )*/ );


	secupress_add_settings_field(
		__( 'Protect the profile page', 'secupress' ),
		array(	'description' => __( 'You can easily protect the user\'s profile settings page by asking them to enter their password.', 'secupress' ),
				'name' => 'profile_protect_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'profile_protect_' . $pluginnow,
				'label'			=> __( 'Yes, protect the profile pages', 'secupress' ),
				'label_for'		=> 'profile_protect_' . $pluginnow,
				'label_screen'	=> __( 'Yes, protect the profile pages', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'profile_protect_' . $pluginnow,
				'class'	=> array( 'hidden', 'block-hidden', 'block-' . 'profile_protect_' . $pluginnow ),
				'description'  => __( 'By using this protection, nobody can stalk into your profile page when you left your computer.', 'secupress' ),
			),
		)
	);

	secupress_add_settings_field(
		sprintf( __( 'Protect %s settings page', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
		array(	'description' => __( 'We recommand to protect the settings page once your settings are done.', 'secupress' ),
				'name' => 'settings_protect_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'settings_protect_' . $pluginnow,
				'label_for'		=> 'settings_protect_' . $pluginnow,
				'label_screen'	=> __( 'Yes, protect the settings pages', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'settings_protect_' . $pluginnow,
				'class'	=> array( 'hidden', 'block-hidden', 'block-' . 'settings_protect_' . $pluginnow ),
				'description'  => __( 'By using this protection, nobody can stalk into the settings page when you left your computer.', 'secupress' ),
			),
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );
