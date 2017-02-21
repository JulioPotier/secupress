<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

$this->set_current_section( 'backup-history' );
$this->add_section( __( 'Backup History', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Backup History', 'secupress' ),
	'name'         => $this->get_field_name( 'backup-history' ),
	'type'         => 'backup_history',
) );
