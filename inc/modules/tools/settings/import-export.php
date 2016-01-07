<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'import_export' );
$this->add_section( __( 'Settings Manager', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Settings Exporter', 'secupress' ),
	'description'  => __( 'Export your settings so you can import them in another website or act just like a backup', 'secupress' ),
	'name'         => $this->get_field_name( 'export_settings' ),
	'type'         => 'export_form',
) );


$this->add_field( array(
	'title'        => __( 'Settings Importer', 'secupress' ),
	'description'  => __( 'Import previously exported settings from another website or from a previous save point', 'secupress' ), //// wording save point
	'label_for'    => 'upload',
	'name'         => $this->get_field_name( 'import_settings' ),
	'type'         => 'import_upload_form',
) );
