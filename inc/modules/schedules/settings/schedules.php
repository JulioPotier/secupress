<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'schedules' );
$this->add_section( __( 'Scheduled', 'secupress' ), array( 'with_save_button' => false ) );


$this->add_field( array(
	'title'        => __( 'Backups', 'secupress' ),
	'description'  => __( 'Do not forget to schedule one backup per week at least!', 'secupress' ),
	'name'         => $this->get_field_name( 'backups' ),
	'type'         => 'scheduled_backups',
) );


$this->add_field( array(
	'title'        => __( 'Scanners', 'secupress' ),
	'description'  => __( 'Do not forget to schedule one scan per week at least!', 'secupress' ),
	'name'         => $this->get_field_name( 'scans' ),
	'type'         => 'scheduled_scans',
) );


$this->add_field( array(
	'title'        => __( 'Files Monitoring', 'secupress' ),
	'description'  => __( 'Do not forget to schedule one monitoring per week at least!', 'secupress' ),
	'name'         => $this->get_field_name( 'filemon' ),
	'type'         => 'scheduled_filemon',
) );
