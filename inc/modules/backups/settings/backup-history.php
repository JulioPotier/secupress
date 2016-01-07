<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-history' );
$this->add_section( __( 'Backup History', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'backup-history' );
$this->add_field(
	__( 'Backup History', 'secupress' ),
	array(
		'name'        => $field_name,
		// 'description' => __( 'Backuping your database daily reduce the risks to lose your content because of an attack.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'backup_history',
		),
	)
);
