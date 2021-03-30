<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'uploads' );
$this->set_section_description( __( 'WordPress allows by default to add a plugin or theme by simply uploading a zip file. This is not secure since the file could contain any custom PHP code.<br/>By removing this possibility you ensure that plugins could only be added using FTP or via the official WordPress repository.', 'secupress' ) );
$this->add_section( __( 'Uploads Themes & Plugins', 'secupress' ) );


$plugin = $this->get_current_plugin();

$this->add_field( array(
	/** Translators: %s is a file extension */
	'title'             => sprintf( __( 'Disallow %s uploads', 'secupress' ), '<code>.zip</code>' ),
	'label_for'         => $this->get_field_name( 'activate' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'plugins-themes', 'uploads' ),
	'label'             => __( 'Yes, disable uploads of themes and plugins', 'secupress' ),
) );
