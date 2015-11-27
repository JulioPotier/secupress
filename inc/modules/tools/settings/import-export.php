<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'import_export' );
$this->add_section( __( 'Settings Manager', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'export_settings' );
$this->add_field(
	__( 'Settings Exporter', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Export your settings so you can import them in another website or act just like a backup', 'secupress' ) . 
						( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s' ) ),
		// 'readonly'    => ! secupress_is_pro(), // done in export_upload_form()
	),
	array(
		array(
			'type'         => 'export_form',
		),
	)
);

$field_name = $this->get_field_name( 'import_settings' );
$this->add_field(
	__( 'Settings Importer', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Import previously exported settings from another website or from a last save point', 'secupress' ) .  //// wording save point
						( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s' ) ),
		// 'readonly'    => ! secupress_is_pro(), // done in import_upload_form()
	),
	array(
		array(
			'type'         => 'import_upload_form',
		),
	)
);
