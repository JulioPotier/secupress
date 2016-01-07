<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-db' );
$this->add_section( __( 'Database Backups', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'backup-db' );
$this->add_field(
	__( 'Do a Database Backup', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Checked tables will be backed up.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'backup_db',
		),
	)
);