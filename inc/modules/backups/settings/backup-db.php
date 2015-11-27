<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'backup-db' );
$this->add_section( __( 'Database Backups', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'backup-db' );
$this->add_field(
	__( 'Database Backups', 'secupress' ),
	array(
		'name'        => $field_name,
		// 'description' => __( 'Backuping your database daily reduce the risks to lose your content because of an attack.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'backup_db',
		),
	)
);