<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

$sectionnow = 'auto_update';
$pluginnow = 'minor_updates';

secupress_add_settings_section( __( 'WordPress Updates', 'secupress' ) );


	$select_args_options = apply_filters( 'module_' . $pluginnow, 
							array(	'-1' 			=> __( 'No thank you', 'secupress' ) . ' <i>(' . __( 'Not recommanded', 'secupress' ) . ')</i>',
									'googleauth'	=> __( 'Google Authenticator', 'secupress' ),
									'_passwordless'	=> __( 'PasswordLess', 'secupress' ) . ' ' . __( '<i>(by mail, iOS or Android notifs)</i>', 'secupress' ),
									'emaillink'		=> __( 'Email Link', 'secupress' ),
									'password'		=> __( 'Additional Password', 'secupress' ),
								) );

	secupress_add_settings_field(
		__( 'Minor Updates', 'secupress' ),
		array(	'description' => __( 'Let WordPress updates itself when a minor version is available.', 'secupress' ),
				'name' => 'plugin_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'checkbox',
				'name'			=> 'plugin_' . $pluginnow,
				'label'			=> __( 'If needed, try to force WordPress to allow auto updates for minor versions.', 'secupress' ),
				'label_for'		=> 'plugin_' . $pluginnow,
				'label_screen'	=> __( 'Allow minor versions updates', 'secupress' ),
			),
			array(
				'type'	=> 'helper_warning',
				'name'	=> 'plugin_' . $pluginnow,
				'class'	=> array( 'block-' . 'plugin_' . $pluginnow ),
				'description'  => __( 'Not allowing this may result using a vulnerable version of WordPress. Usually, minor versions are safe to update and contains security fixes.', 'secupress' ),
			),			
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );