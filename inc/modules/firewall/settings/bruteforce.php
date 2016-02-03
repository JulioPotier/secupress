<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'brutefoce' );
$this->add_section( __( 'Anti Bruteforce Managment', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'Use the Anti Bruteforce', 'secupress' ),
	'description'       => __( 'When a single visitor (IP Address) is hitting hard on your website, like 10 pages per second, we should tell him to go slowly, and if it continues, lock its IP Address.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bruteforce' ),
	'label'             => __( 'Yes, i want to use the Anti-Bruteforce on my website', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'This will be used on your front-end, back-end and the login form.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'This is NOT an anti login bruteforce, if you want this kind of module, just activate the <a href="%s#logincontrol">Login Attempts Blocker</a>.', 'secupress' ), secupress_admin_url( 'modules', 'users-login' ) ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'How many requests per second minimum before blocking?', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s', 'secupress' ), '9' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'request_number' ),
	'type'         => 'number',
	'label_after'  => __( 'requests per second', 'secupress' ),
	'default'      => '9',
	'attributes'   => array(
		'min' => 3,
		'max' => 1000,
	),
) );


$this->add_field( array(
	'title'        => __( 'How long should we ban?', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'time_ban' ),
	'type'         => 'number',
	'label_after'  => _x( 'min', 'minute', 'secupress' ),
	'default'      => '5',
	'attributes'   => array(
		'min' => 1,
		'max' => 60,
	),
) );
