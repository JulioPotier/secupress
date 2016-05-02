<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'plugins_themes' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your plugins.', 'secupress' ) );
$this->add_section( __( 'Plugins Page', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	'title'             => __( 'Plugins updates', 'secupress' ),
	'label_for'         => $this->get_field_name( 'update' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-update' ),
	'label'             => __( 'Yes, disable the updates for all plugins', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Plugins installation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'installation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-installation' ),
	'label'             => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'This will also disable plugins upload.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Plugins activation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-activation' ),
	'label'             => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
) );


$this->add_field( array(
	'title'             => __( 'Plugins deactivation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'deactivation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-deactivation' ),
	'label'             => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
) );


$this->add_field( array(
	'title'             => __( 'Plugins deletion', 'secupress' ),
	'label_for'         => $this->get_field_name( 'deletion' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'plugin-deletion' ),
	'label'             => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
) );


$main_field_name = $this->get_field_name( 'detect_bad_plugins' );

$this->add_field( array(
	'title'             => __( 'Detect Bad Plugins', 'secupress' ),
	'description'       => __( 'Work for any public plugin (premium and free).', 'secupress' ),
	'plugin_activation' => true,
	'label_for'         => $main_field_name,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'detect-bad-plugins' ),
	'label'             => __( 'Yes, enable the detection if a plugin I use is known as vulnerable', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Based on our Daily Security Monitoring, we will push notices for plugins newly known as vulnerables.', 'secupress' ),
		),
	),
) );
