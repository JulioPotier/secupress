<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	'title'        => __( 'Theme update', 'secupress' ),
	'label_for'    => $this->get_field_name( 'update' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-update' ),
	'label'        => __( 'Yes, disable updates for themes', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'Theme installation', 'secupress' ),
	'label_for'    => $this->get_field_name( 'installation' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-installation' ),
	'label'        => __( 'Yes, disable the installation for themes', 'secupress' ),
) );


$this->add_field( array(
	'title'        => __( 'Theme switch', 'secupress' ),
	'label_for'    => $this->get_field_name( 'activation' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-activation' ),
	'label'        => __( 'Yes, disable switch theme', 'secupress' ),
) );


$this->add_field( array(
	'title'        => __( 'Theme deletion', 'secupress' ),
	'label_for'    => $this->get_field_name( 'deletion' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'theme-deletion' ),
	'label'        => __( 'Yes, disable delete for theme', 'secupress' ),
) );


$main_field_name = $this->get_field_name( 'detect_bad_themes' );

$this->add_field( array(
	'title'        => __( 'Detect Bad Themes', 'secupress' ),
	'description'  => __( 'Work for any public theme, premium or free.', 'secupress' ),
	'label_for'    => $main_field_name,
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-themes' ),
	'label'        => __( 'Yes, enable the detection if a theme I use is known as vulnerable', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Based on our Daily Security Monitoring, we will push notices for themes newly known as vulnerables.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'Auto-Update Bad Themes', 'secupress' ),
	'description'  => __( 'Only for themes from official repository.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'autoupdate_bad_themes' ),
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'plugins-themes', 'autoupdate-bad-themes' ),
	'label'        => __( 'Yes, enable the auto-update if a theme I use is known as vulnerable', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Based on our Daily Security Monitoring, we will push updates for themes newly known as vulnerables.', 'secupress' ),
		),
	),
) );
