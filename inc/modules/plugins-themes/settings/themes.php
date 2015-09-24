<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'themes_plugins' );
$this->set_section_description( __( 'By using these protections, you can easily select the proper allowed actions on your themes.', 'secupress' ) );
$this->add_section( __( 'Themes Page', 'secupress' ) );


$plugin = $this->get_current_plugin(); // 'themes'
$field_name = $this->get_field_name( 'installation' );

$this->add_field(
	__( 'Theme installation', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable the installation for themes', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable the installation for themes', 'secupress' ),
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
	__( 'Theme switch', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable switch theme', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable switch theme', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'deletion' );
$this->add_field(
	__( 'Theme deletion', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable delete for theme', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable delete for theme', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_deletion_' . $plugin,
			'class'        => array( 'block-' . $field_name ),
		),
	)
);

$field_name = $this->get_field_name( 'update' );
$this->add_field(
	__( 'Theme update', 'secupress' ),
	array(
		'name'        => $field_name,
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable updates for themes', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable updates for themes', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'class'        => array( 'block-' . $field_name ),
			'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);