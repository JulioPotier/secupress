<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'plugins_themes' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your plugins.', 'secupress' ) );
$this->add_section( __( 'Plugins Page', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'plugins'


$field_name = $this->get_field_name( 'installation' );
$this->add_field(
	__( 'Plugins installation', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the installation of all new plugins', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'activation' );
$this->add_field(
	__( 'Plugins activation', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the activation action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'activation' );
$this->add_field(
	__( 'Plugins deactivation', 'secupress' ),
	array(
		'name'        => $plugin . '_deactivation',
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_deactivation_' . $plugin,
			'label'        => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
			'label_for'    => 'plugin_deactivation_' . $plugin,
			'label_screen' => __( 'Yes, disable the deactivation action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_deactivation_' . $plugin,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'deletion' );
$this->add_field(
	__( 'Plugins deletion', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the deletion action for every plugin', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'update' );
$this->add_field(
	__( 'Plugins updates', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable the updates for all plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the updates for all plugins', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
			'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);