<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

$sectionnow = 'plugins_themes';
$pluginnow = 'plugins';

secupress_add_settings_section( __( 'Plugins Page', 'secupress' ) );


	secupress_add_settings_field(
		__( 'Plugins installation', 'secupress' ),
		array(	
				'name' => 'plugin_install_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_install_' . $pluginnow,
				'label'			=> __( 'Yes, disable the installation of all new plugins', 'secupress' ),
				'label_for'		=> 'plugin_install_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the installation of all new plugins', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_install_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_install_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Plugins activation', 'secupress' ),
		array(	
				'name' => 'plugin_activation_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_activation_' . $pluginnow,
				'label'			=> __( 'Yes, disable the activation action for every plugin', 'secupress' ),
				'label_for'		=> 'plugin_activation_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the activation action for every plugin', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_activation_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_activation_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Plugins deactivation', 'secupress' ),
		array(	
				'name' => 'plugin_deactivation_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_deactivation_' . $pluginnow,
				'label'			=> __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
				'label_for'		=> 'plugin_deactivation_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_deactivation_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_deactivation_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Plugins deletion', 'secupress' ),
		array(	
				'name' => 'plugin_deletion_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_deletion_' . $pluginnow,
				'label'			=> __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
				'label_for'		=> 'plugin_deletion_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_deletion_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_deletion_' . $pluginnow ),
			),
		)
	);

	secupress_add_settings_field(
		__( 'Plugins updates', 'secupress' ),
		array(	
				'name' => 'plugin_update_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_update_' . $pluginnow,
				'label'			=> __( 'Yes, disable the updates for all plugins', 'secupress' ),
				'label_for'		=> 'plugin_update_' . $pluginnow,
				'label_screen'	=> __( 'Yes, disable the updates for all new plugins', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'description' => 'You\'ll still be notified when an update is available.',
				'name'	=> 'plugin_update_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_update_' . $pluginnow ),
			),
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );