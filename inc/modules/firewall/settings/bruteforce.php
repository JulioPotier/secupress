<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'brutefoce' );
$this->add_section( __( 'Anti Brute-Force Management', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'Use Anti Brute-Force', 'secupress' ),
	'description'       => __( 'When a single visitor (IP Address) is hitting your website hard (10 times per second), (s)he should go slowly, and if (s)he continues, lock their IP Address.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bruteforce' ),
	'label'             => __( 'Yes, use Anti Brute-Force on my website', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Used on your all WordPress pages.', 'secupress' ),
		),
		array(
			'type'        => 'help',
			'description' => __( 'Requests done by logged-in administrators and AJAX requests are not blocked.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => sprintf( __( 'This is NOT an anti login brute-force, if you want this kind of module, just activate the <a href="%s#row-login-protection_type">Login Attempts Blocker</a>.', 'secupress' ), esc_url( secupress_admin_url( 'modules', 'users-login' ) ) ),
		),
	),
) );
