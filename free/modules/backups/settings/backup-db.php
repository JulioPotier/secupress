<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'backup-db' );
$this->add_section( __( 'Database Backups', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Run a Database Backup', 'secupress' ),
	'description'  => __( 'Checked tables will be backed up.', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-db' ),
	'type'         => 'backup_db',
) );
