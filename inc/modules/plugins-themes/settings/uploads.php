<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'uploads' );
$this->set_section_description( __( 'WordPress allows dy default to add a plugin or theme by simply uploading a zip file. This is not secure since the file can contain any custom php code.<br>By removing this possibility you ensure that plugins could only be added using the FTP or came from the official repository.', 'secupress' ) );
$this->add_section( __( 'Themes & Plugins Uploads', 'secupress' ) );


$plugin = $this->get_current_plugin();

$field_name = $this->get_field_name( 'uploads' );
$this->add_field(
	__( 'Disallow .zip uploads', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => secupress_is_pro() ? '' : secupress_get_pro_version_string(),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, disable uploads for themes and plugins', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, disable uploads for themes and plugins', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			// 'description'  => __( 'You will still be notified when an update is available.', 'secupress' ),
		),
	)
);