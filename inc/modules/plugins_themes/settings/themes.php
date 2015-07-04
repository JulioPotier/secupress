<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

$sectionnow = 'themes_plugins';
$pluginnow = 'themes';

secupress_add_settings_section( __( 'Themes Page', 'secupress' ) );


	secupress_add_settings_field(
		__( 'Theme installation', 'secupress' ),
		array(	
				'name' => 'theme_install_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'theme_install_' . $pluginnow,
				'label'			=> __( 'Yes, disable the installation for themes', 'secupress' ),
				'label_for'		=> 'theme_install_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the installation for themes', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'theme_install_' . $pluginnow,
				'class'	=> array( 'block-' . 'theme_install_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Theme switch', 'secupress' ),
		array(	
				'name' => 'theme_activation_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'theme_activation_' . $pluginnow,
				'label'			=> __( 'Yes, disable switch theme', 'secupress' ),
				'label_for'		=> 'theme_activation_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable switch theme', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'theme_activation_' . $pluginnow,
				'class'	=> array( 'block-' . 'theme_activation_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Theme deletion', 'secupress' ),
		array(	
				'name' => 'theme_deletion_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'theme_deletion_' . $pluginnow,
				'label'			=> __( 'Yes, disable delete for theme', 'secupress' ),
				'label_for'		=> 'theme_deletion_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable delete for theme', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_deletion_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_deletion_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Theme update', 'secupress' ),
		array(	
				'name' => 'theme_update_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'theme_update_' . $pluginnow,
				'label'			=> __( 'Yes, disable updates for themes', 'secupress' ),
				'label_for'		=> 'theme_update_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable updates for themes', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'description' => 'You\'ll still be notified when an update is available.',
				'name'	=> 'theme_update_' . $pluginnow,
				'class'	=> array( 'block-' . 'theme_update_' . $pluginnow ),
			),
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );