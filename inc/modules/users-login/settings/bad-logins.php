<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'login_auth2' );
$this->add_section( __( 'Limit Login Attempts', 'secupress' ) );


$main_field_name = $this->get_field_name( 'type' );

$select_args_options = apply_filters( $main_field_name, array(
	'limitloginattempts' => __( 'Limit the number of bad login attempts', 'secupress' ),
	'_ooc'               => __( 'Use the Only One Connection mode', 'secupress' ),
	'bannonexistsuser'   => __( 'Ban login attempts on non-existing usernames', 'secupress' ),
	'nonlogintimeslot'   => __( 'Set a non-login time slot', 'secupress' ),
) );

$this->add_field(
	__( 'Use an attempt blocker', 'secupress' ),
	array(
		'name'        => $main_field_name,
		'description' => __( 'You can temporary ban people who try to mess with the login page. This is recommended to avoid to be victim of a brute-force.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkboxes',
			'options'      => $select_args_options,
			'name'         => $main_field_name,
			'label_for'    => $main_field_name,
			'label_screen' => __( 'Use an attempt blocker', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'Premium Upgrade', 'secupress' ),
	array(
		'name'       => '',
		'field_type' => 'field_button',
	),
	array(
		'depends_on'         => $main_field_name . '__ooc',
		'helper_description' => array(
			'description'    => __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' ) . '<br>' . __( 'Once logged in, nobody can log in on your account at the same time as you.', 'secupress' ),
		),
		'button'             => array(
			'url'            => '#',
			'button_label'   => __( 'I Upgrade Now', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'number_attempts' );

$this->add_field(
	__( 'How many attempts before a ban?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '10 - 50' ),
	),
	array(
		'depends_on'       => $main_field_name . '_limitloginattempts ' . $main_field_name . '_bannonexistsuser',
		array(
			'type'         => 'number',
			'min'          => 3,
			'max'          => 99,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => '',
			'default'      => '10',
			'label_screen' => __( 'How many attempt before a ban?', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'time_ban' );

$this->add_field(
	__( 'How long should we ban?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	),
	array(
		'depends_on'       => $main_field_name . '_limitloginattempts ' . $main_field_name . '_bannonexistsuser',
		array(
			'type'         => 'number',
			'min'          => 1,
			'max'          => 60,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => __( ' mn', 'secupress' ),
			'default'      => '5',
			'label_screen' => __( 'How long should we ban?', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'nonlogintimeslot' );

$this->add_field(
	__( 'Non-Login time slot settings', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => '',
	),
	array(
		'depends_on'       => $main_field_name . '_nonlogintimeslot',
		array(
			'type'         => 'nonlogintimeslot',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => '',
			'label_screen' => __( 'Non-Login time slot', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Select the range of time you need to disallow logins.', 'secupress' ),
		),
	)
);
