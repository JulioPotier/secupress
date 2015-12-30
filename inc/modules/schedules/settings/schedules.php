<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'schedules' );
$this->add_section( __( 'Scheduled', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'backups' );
$this->add_field(
	__( 'Backups', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Do not forget to schedule one backup per week at least!', 'secupress' ),
	),
	array(
		array(
			'type'         => 'scheduled_backups',
		),
	)
);

$field_name = $this->get_field_name( 'scans' );
$this->add_field(
	__( 'Scanners', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Do not forget to schedule one scan per week at least!', 'secupress' ),
	),
	array(
		array(
			'type'         => 'schedules_scans',
		),
	)
);

$field_name = $this->get_field_name( 'filemon' );
$this->add_field(
	__( 'Files Monitoring', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Do not forget to schedule one monitoring per week at least!', 'secupress' ),
	),
	array(
		array(
			'type'         => 'schedules_filemon',
		),
	)
);
