<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-file' );
$this->add_section( __( 'Files Backups', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'backup-file' );
$this->add_field(
	__( 'Files Backups', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => ( secupress_is_pro() ? '' : secupress_get_pro_version_string() ),
		// 'readonly'     => ! secupress_is_pro(), // done by backup_file()
	),
	array(
		array(
			'type'         => 'backup_file',
		),
	)
);
