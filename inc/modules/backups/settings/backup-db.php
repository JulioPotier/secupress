<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-db' );
$this->add_section( __( 'Database Backups', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Backup History', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-history' ),
	'type'         => 'backup_history',
) );


$this->add_field( array(
	'title'        => __( 'Do a Database Backup', 'secupress' ),
	'description'  => __( 'Checked tables will be backed up.', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-db' ),
	'type'         => 'backup_db',
) );
