<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'themes'


$this->add_field(
	__( 'Theme installation', 'secupress' ),
	array(
		'name'        => 'theme_install_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'theme_install_' . $plugin,
			'label'        => __( 'Yes, disable the installation for themes', 'secupress' ),
			'label_for'    => 'theme_install_' . $plugin,
			'label_screen' => __( 'Yes, disable the installation for themes', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'theme_install_' . $plugin,
			'class'        => array( 'block-theme_install_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Theme switch', 'secupress' ),
	array(
		'name'        => 'theme_activation_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'theme_activation_' . $plugin,
			'label'        => __( 'Yes, disable switch theme', 'secupress' ),
			'label_for'    => 'theme_activation_' . $plugin,
			'label_screen' => __( 'Yes, disable switch theme', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'theme_activation_' . $plugin,
			'class'        => array( 'block-theme_activation_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Theme deletion', 'secupress' ),
	array(
		'name'        => 'theme_deletion_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'theme_deletion_' . $plugin,
			'label'        => __( 'Yes, disable delete for theme', 'secupress' ),
			'label_for'    => 'theme_deletion_' . $plugin,
			'label_screen' => __( 'Yes, disable delete for theme', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_deletion_' . $plugin,
			'class'        => array( 'block-plugin_deletion_' . $plugin ),
		),
	)
);

$this->add_field(
	__( 'Theme update', 'secupress' ),
	array(
		'name'        => 'theme_update_' . $plugin,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'theme_update_' . $plugin,
			'label'        => __( 'Yes, disable updates for themes', 'secupress' ),
			'label_for'    => 'theme_update_' . $plugin,
			'label_screen' => __( 'Yes, disable updates for themes', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'theme_update_' . $plugin,
			'class'        => array( 'block-theme_update_' . $plugin ),
			'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);
