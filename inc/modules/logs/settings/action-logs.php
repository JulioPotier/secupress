<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'action-logs' );
$this->add_section( __( 'Logs', 'secupress' ), array( 'with_save_button' => false ) );

$field_name      = $this->get_field_name( 'action-logs' );
$main_field_name = $field_name;
$this->add_field(
	__( 'WordPress Logs', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'What happened on your WordPress website? By activating this module, we will record the most sensible actions, lighly.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, i want to log WordPress actions', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to log WordPress actions', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'We will not log post action like creation, update, or theme switched but rather password and profile update, email changes, new administrator user, admin has logged in ...', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'wp-logs' );
$this->add_field(
	__( 'WordPress Logs', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'What happened on your WordPress website?', 'secupress' ),
	),
	array(
		'depends'          => $main_field_name,
		array(
			'type'         => 'wp_logs',
		),
	)
);