<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

// Add the form manually.
add_action( 'secupress.settings.before_section_import_export', array( $this, 'print_open_form_tag' ) );
add_action( 'secupress.settings.after_section_import_export', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'import_export' );
$this->add_section( __( 'Settings Manager', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Settings Exporter', 'secupress' ),
	'description'  => __( 'Export your settings so you can import them into another website or keep them as backup.', 'secupress' ),
	'name'         => $this->get_field_name( 'export_settings' ),
	'type'         => 'export_form',
) );


$this->add_field( array(
	'title'        => __( 'Settings Importer', 'secupress' ),
	'description'  => __( 'Import previously exported settings from another website or from a previous save.', 'secupress' ),
	'label_for'    => 'upload',
	'name'         => $this->get_field_name( 'import_settings' ),
	'type'         => 'import_upload_form',
) );

$this->add_field( array(
	'title'        => __( 'Reset All Settings', 'secupress' ),
	'description'  => __( 'Set the settings like a fresh install.', 'secupress' ),
	'label_for'    => 'reset_all_settings',
	'name'         => $this->get_field_name( 'reset_all_settings' ),
	'type'         => 'reset_settings_button',
) );
