<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'alerts' );
$this->add_section( __( 'Alerts Manager', 'secupress' ), array( 'with_save_button' => false ) );

$field_name = $this->get_field_name( 'alerts' );
$this->add_field(
	__( 'Alerts', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( '', 'secupress' ),
	),
	array(
		array(
			'type'         => 'alerts', //// décompiler le tout et faire un module par alerte genre 404, login, requests etc
		),
	)
);