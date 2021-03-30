<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'backup-file' );
$this->add_section( __( 'Files Backup', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Run a Files Backup', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-file' ),
	'type'         => 'backup_files',
) );
