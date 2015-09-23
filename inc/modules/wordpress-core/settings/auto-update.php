<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'minor_updates' );
$this->add_section( __( 'WordPress Updates', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'auto_update'


$select_args_options = apply_filters( 'module_' . $plugin, array(
	'-1'            => __( 'No thank you', 'secupress' ) . ' <i>(' . __( 'Not recommanded', 'secupress' ) . ')</i>',
	'googleauth'    => __( 'Google Authenticator', 'secupress' ),
	'_passwordless' => __( 'PasswordLess', 'secupress' ) . ' ' . __( '<i>(by mail, iOS or Android notifs)</i>', 'secupress' ),
	'emaillink'     => __( 'Email Link', 'secupress' ),
	'password'      => __( 'Additional Password', 'secupress' ),
) );

$this->add_field(
	__( 'Minor Updates', 'secupress' ),
	array(
		'name'        => 'plugin_' . $plugin,
		'description' => __( 'Let WordPress updates itself when a minor version is available.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_' . $plugin,
			'label'        => __( 'If needed, try to force WordPress to allow auto updates for minor versions.', 'secupress' ),
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Allow minor versions updates', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'block-plugin_' . $plugin ),
			'description'  => __( 'Not allowing this may result using a vulnerable version of WordPress. Usually, minor versions are safe to update and contains security fixes.', 'secupress' ),
		),
	)
);
