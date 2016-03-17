<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'brutefoce' );
$this->add_section( __( 'Anti Bruteforce Managment', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'Use the Anti Bruteforce', 'secupress' ),
	'description'       => __( 'When a single visitor (IP Address) is hitting hard on your website (10 pages per second), we should tell him to go slowly, and if it continues, lock its IP Address.', 'secupress' ),
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
			'type'        => 'help',
			'description' => __( 'Requests done by logged in administrators and AJAX requests are not blocked.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'This is NOT an anti login bruteforce, if you want this kind of module, just activate the <a href="%s#logincontrol">Login Attempts Blocker</a>.', 'secupress' ), secupress_admin_url( 'modules', 'users-login' ) ),
		),
	),
) );