<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions for your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	'title'             => __( 'Theme installation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'installation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-installation' ),
	'label'             => __( 'Yes, disable the installation for themes', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Disable theme upload.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Theme switch', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-activation' ),
	'label'             => __( 'Yes, disable switch theme', 'secupress' ),
) );


$this->add_field( array(
	'title'             => __( 'Theme deletion', 'secupress' ),
	'label_for'         => $this->get_field_name( 'deletion' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-deletion' ),
	'label'             => __( 'Yes, disable deletion of themes', 'secupress' ),
) );


$main_field_name = $this->get_field_name( 'detect_bad_themes' );

$this->add_field( array(
	'title'             => __( 'Detect Bad Themes', 'secupress' ),
	'description'       => __( 'Work for any public theme, premium or free.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ),
	'label'             => __( 'Yes, enable the detection of themes with known vulnerabilites', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Based on our Daily Security Monitoring, notices will be displayed for themes newly detected as vulnerable.', 'secupress' ),
		),
	),
) );
