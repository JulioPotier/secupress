<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'alerts' );
$this->add_section( __( 'Alerts Manager', 'secupress' ), array( 'with_save_button' => false ) );

$this->add_field( array(
	'title'        => __( 'Alerts', 'secupress' ),
	'description'  => __( '', 'secupress' ),
	'name'         => $this->get_field_name( 'alerts' ),
	'type'         => 'alerts', //// décompiler le tout et faire un module par alerte genre 404, login, requests etc
) );
