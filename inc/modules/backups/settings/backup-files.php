<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-file' );
$this->add_section( __( 'Files Backups', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Do a Files Backups', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-file' ),
	'type'         => 'backup_files',
) );