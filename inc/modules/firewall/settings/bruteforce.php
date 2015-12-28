<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'brutefoce' );
$this->add_section( __( 'Anti Bruteforce Managment', 'secupress' ) );


$field_name      = $this->get_field_name( 'activated' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Use the Anti Bruteforce', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'When a single visitor (IP Address) is hitting hard on your website, like 10 pages per second, we should tell him to go slowly, and if it continues, lock its IP Address.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'firewall', 'bruteforce' ),
			'label'        => __( 'Yes, i want to use the Anti Bruteforce on my website', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to use the Anti Bruteforce on my website', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'This will be used on your front-end, back-end and the login form.', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => $field_name,
			'description'  => sprintf( __( 'This is NOT an anti login bruteforce, if you want this kind of module, just activate the <a href="%s#logincontrol">Login Attempts Blocker</a>.', 'secupress' ), secupress_admin_url( 'modules', 'users-login' ) ),
		),
	)
);


$field_name = $this->get_field_name( 'request_number' );

$this->add_field(
	__( 'How many requests per second minimum before blocking?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '9' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'number',
			'min'          => 3,
			'max'          => 1000,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => __( ' requests per second', 'secupress' ),
			'default'      => '9',
			'label_screen' => __( 'How many requests per second before blocking?', 'secupress' ),
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
		'depends'     => $main_field_name,
		array(
			'type'         => 'number',
			'min'          => 1,
			'max'          => 60,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => _x( ' mn', 'minute', 'secupress' ),
			'default'      => '5',
			'label_screen' => __( 'How long should we ban?', 'secupress' ),
		),
	)
);
